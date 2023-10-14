#include "server.h"
#include "external_prod.h"
#include "utils.h"
#include <bitset>
#include <cassert>
#include <cstdlib>
#include <memory>
#include <stdexcept>

PirServer::PirServer(const PirParams &pir_params)
    : pir_params_(pir_params), context_(pir_params.get_seal_params()),
      DBSize_(pir_params.get_DBSize()), evaluator_(context_), dims_(pir_params.get_dims()) {}

// Fills the database with random data
void PirServer::gen_data() {
  std::vector<Entry> data;
  data.reserve(pir_params_.get_num_entries());
  for (size_t i = 0; i < pir_params_.get_num_entries(); ++i) {
    data.push_back(Entry(pir_params_.get_entry_size()));
    for (size_t j = 0; j < pir_params_.get_entry_size(); ++j) {
      data[i][j] = (rand() % 255);
    }
  }
  set_database(data);
}

std::vector<seal::Ciphertext>
PirServer::evaluate_first_dim(std::vector<seal::Ciphertext> &selection_vector) {
  int size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Ciphertext> result;

  for (int i = 0; i < size_of_other_dims; i++) {
    seal::Ciphertext cipher_result;
    evaluator_.multiply_plain(selection_vector[0], db_[i], cipher_result);
    result.push_back(cipher_result);
  }

  for (int i = 1; i < selection_vector.size(); i++) {
    for (int j = 0; j < size_of_other_dims; j++) {
      seal::Ciphertext cipher_result;
      evaluator_.multiply_plain(selection_vector[i], db_[i * size_of_other_dims + j],
                                cipher_result);
      evaluator_.add_inplace(result[j], cipher_result);
    }
  }

  for (auto &ct : result) {
    evaluator_.transform_from_ntt_inplace(ct);
  }

  return result;
}

// Computes a dot product between the selection vector and the database for the
// first dimension with a delayed modulus optimization. Selection vector should
// be transformed to ntt.
std::vector<seal::Ciphertext>
PirServer::evaluate_first_dim_delayed_mod(std::vector<seal::Ciphertext> &selection_vector) {
  int size_of_other_dims = DBSize_ / dims_[0];
  std::vector<seal::Ciphertext> result;
  auto seal_params = context_.get_context_data(selection_vector[0].parms_id())->parms();
  // auto seal_params =  context_.key_context_data()->parms();
  auto coeff_modulus = seal_params.coeff_modulus();
  size_t coeff_count = seal_params.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t encrypted_ntt_size = selection_vector[0].size();
  seal::Ciphertext ct_acc;

  for (int i = 0; i < dims_[0]; i++) {
    evaluator_.transform_to_ntt_inplace(selection_vector[i]);
  }

  for (int col_id = 0; col_id < size_of_other_dims; ++col_id) {
    std::vector<std::vector<uint128_t>> buffer(
        encrypted_ntt_size, std::vector<uint128_t>(coeff_count * coeff_mod_count, 0));
    for (int i = 0; i < dims_[0]; i++) {
      // std::cout << "i: " << i << std::endl;
      for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++) {
        utils::multiply_poly_acum(selection_vector[i].data(poly_id),
                                  db_[col_id + i * size_of_other_dims].data(),
                                  coeff_count * coeff_mod_count, buffer[poly_id].data());
      }
    }
    ct_acc = selection_vector[0];
    for (size_t poly_id = 0; poly_id < encrypted_ntt_size; poly_id++) {
      auto ct_ptr = ct_acc.data(poly_id);
      auto pt_ptr = buffer[poly_id];
      for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
        auto mod_idx = (mod_id * coeff_count);

        for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
          pt_ptr[coeff_id + mod_idx] =
              pt_ptr[coeff_id + mod_idx] % static_cast<__uint128_t>(coeff_modulus[mod_id].value());
          ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx]);
        }
      }
    }
    evaluator_.transform_from_ntt_inplace(ct_acc);
    result.push_back(ct_acc);
  }

  return result;
}

std::vector<seal::Ciphertext>
PirServer::evaluate_gsw_product(std::vector<seal::Ciphertext> &result,
                                std::vector<GSWCiphertext> &selection_vector) {
  std::vector<seal::Ciphertext> result_vector;
  auto block_size = result.size() / selection_vector.size();

  for (int i = 0; i < block_size; i++) {
    std::cout << "ORIG noise: " << decryptor_->invariant_noise_budget(result[i]) << std::endl;
    gsw::external_product(selection_vector[0], result[i], result[0].size(), result[i]);
    std::cout << "PROD noise: " << decryptor_->invariant_noise_budget(result[i]) << std::endl;
    result_vector.push_back(result[i]);
  }

  for (int i = 1; i < selection_vector.size(); i++) {
    for (int j = 0; j < block_size; j++) {
      gsw::external_product(selection_vector[i], result[j + i * block_size], result[0].size(),
                            result[j + i * block_size]);
      evaluator_.add_inplace(result_vector[j], result[j + i * block_size]);
    }
  }

  return result_vector;
}

std::vector<seal::Ciphertext> PirServer::expand_query(uint32_t client_id,
                                                      seal::Ciphertext ciphertext) {
  seal::EncryptionParameters params = pir_params_.get_seal_params();
  std::vector<Ciphertext> expanded_query;
  int poly_degree = params.poly_modulus_degree();

  // Expand ciphertext into 2^expansion_factor individual ciphertexts (number of
  // bits)
  int exp = dims_[0] + pir_params_.get_l() * (dims_.size() - 1) * 2;

  int expansion_factor = 0;

  while ((1 << expansion_factor) < exp) {
    expansion_factor++;
  }

  std::vector<Ciphertext> cipher_vec((size_t)pow(2, expansion_factor));
  cipher_vec[0] = ciphertext;

  for (size_t a = 0; a < expansion_factor; a++) {

    int expansion_const = pow(2, a);

    for (size_t b = 0; b < expansion_const; b++) {
      Ciphertext cipher0 = cipher_vec[b];
      evaluator_.apply_galois_inplace(cipher0, poly_degree / expansion_const + 1,
                                      client_galois_keys_[client_id]);
      Ciphertext cipher1;
      utils::shift_polynomial(params, cipher0, cipher1, -expansion_const);
      utils::shift_polynomial(params, cipher_vec[b], cipher_vec[b + expansion_const],
                              -expansion_const);
      evaluator_.add_inplace(cipher_vec[b], cipher0);
      evaluator_.sub_inplace(cipher_vec[b + expansion_const], cipher1);
    }
  }

  return cipher_vec;
}

void PirServer::set_client_galois_key(uint32_t client_id, seal::GaloisKeys client_key) {
  client_galois_keys_[client_id] = client_key;
}

void PirServer::set_client_gsw_key(uint32_t client_id, GSWCiphertext &&gsw_key) {
  client_gsw_keys_[client_id] = gsw_key;
}

std::vector<seal::Ciphertext> PirServer::make_query(uint32_t client_id, PirQuery query) {
  std::vector<seal::Ciphertext> query_vector = expand_query(client_id, query);

  std::vector<seal::Ciphertext> result = evaluate_first_dim_delayed_mod(query_vector);

  int ptr = dims_[0];
  auto l = pir_params_.get_l();
  for (int i = 1; i < dims_.size(); i++) {
    std::vector<GSWCiphertext> gsw_vector(dims_[i]);

    for (int j = 0; j < dims_[i]; j++) {
      std::vector<seal::Ciphertext> lwe_vector;
      for (int k = 0; k < l; k++) {
        lwe_vector.push_back(query_vector[ptr]);
        ptr += 1;
      }
      gsw::query_to_gsw(lwe_vector, client_gsw_keys_[client_id], gsw_vector[j]);
    }
    result = evaluate_gsw_product(result, gsw_vector);
  }

  return result;
}

std::vector<seal::Ciphertext> PirServer::make_query_delayed_mod(uint32_t client_id,
                                                                PirQuery query) {
  std::vector<seal::Ciphertext> first_dim_selection_vector = expand_query(client_id, query);

  std::vector<seal::Ciphertext> result = evaluate_first_dim_delayed_mod(first_dim_selection_vector);

  return result;
}

std::vector<seal::Ciphertext> PirServer::make_query_regular_mod(uint32_t client_id,
                                                                PirQuery query) {
  std::vector<seal::Ciphertext> first_dim_selection_vector = expand_query(client_id, query);

  std::vector<seal::Ciphertext> result = evaluate_first_dim(first_dim_selection_vector);

  return result;
}

void PirServer::set_database(std::vector<Entry> new_db) {
  db_ = Database();

  // Flattens data into vector of u8s and pads each entry with 0s to entry_size
  // number of bytes.
  for (Entry &entry : new_db) {
    if (entry.size() <= pir_params_.get_entry_size()) {
      entry.resize(pir_params_.get_entry_size(), 0);
    } else {
      throw std::invalid_argument("Entry size is too large");
    }
  }

  size_t bits_per_coeff = pir_params_.get_num_bits_per_coeff();
  size_t num_coeffs = pir_params_.get_seal_params().poly_modulus_degree();
  size_t num_bits_per_plaintext = num_coeffs * bits_per_coeff;
  size_t num_entries_per_plaintext = pir_params_.get_num_entries_per_plaintext();
  size_t num_plaintexts = new_db.size() / num_entries_per_plaintext;

  db_ = Database();

  const uint128_t coeff_mask = (1 << (bits_per_coeff)) - 1;
  uint128_t data_buffer = 0;
  uint8_t data_offset = 0;
  for (int i = 0; i < num_plaintexts; i++) {
    uint128_t data_buffer = 0;
    uint8_t data_offset = 0;
    seal::Plaintext plaintext(num_coeffs);

    int index = 0;
    for (int j = num_entries_per_plaintext * i;
         j < std::min(num_entries_per_plaintext * (i + 1), new_db.size()); j++) {
      for (int k = 0; k < pir_params_.get_entry_size(); k++) {
        data_buffer += new_db[j][k] << data_offset;
        data_offset += 8;
        while (data_offset >= bits_per_coeff) {
          plaintext[index] = data_buffer & coeff_mask;
          index++;
          data_buffer >>= bits_per_coeff;
          data_offset -= bits_per_coeff;
        }
      }
    }
    if (data_offset > 0) {
      plaintext[index] = data_buffer & coeff_mask;
      index++;
    }
    db_.push_back(plaintext);
  }

  // Pad database with plaintext of 1s until DBSize_
  for (size_t i = db_.size(); i < DBSize_; i++) {
    db_.push_back(seal::Plaintext("1"));
  }

  // Process database
  preprocess_ntt();
}

void PirServer::preprocess_ntt() {
  for (auto &plaintext : db_) {
    evaluator_.transform_to_ntt_inplace(plaintext, context_.first_parms_id());
  }
}