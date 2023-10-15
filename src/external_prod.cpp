#include "external_prod.h"
#include "seal/util/polyarithsmallmod.h"
#include "utils.h"
#include <cassert>

namespace gsw {
uint64_t l;
uint64_t base_log2;
seal::SEALContext const *context;
} // namespace gsw

// Here we compute a cross product between the transpose of the decomposed BFV
// (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of
// polynomials) to obtain a size-2 vector of polynomials, which is exactly our
// result ciphertext. We use an NTT multiplication to speed up polynomial
// multiplication, assuming that both the GSWCiphertext and decomposed bfv is in
// polynomial coefficient representation.

void gsw::gsw_ntt_negacyclic_harvey(GSWCiphertext &gsw) {
  const auto &context_data = context->first_context_data();
  auto &parms2 = context_data->parms();
  auto &coeff_modulus = parms2.coeff_modulus();
  size_t coeff_count = parms2.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  auto ntt_tables = context_data->small_ntt_tables();

  for (auto &poly : gsw) {
    seal::util::CoeffIter gsw_poly_ptr(poly.data());
    for (int i = 0; i < coeff_mod_count; i++) {
      seal::util::ntt_negacyclic_harvey(gsw_poly_ptr + coeff_count * i, *(ntt_tables + i));
    }
    seal::util::CoeffIter gsw_poly_ptr2(poly.data() + coeff_count * coeff_mod_count);
    for (int i = 0; i < coeff_mod_count; i++) {
      seal::util::ntt_negacyclic_harvey(gsw_poly_ptr2 + coeff_count * i, *(ntt_tables + i));
    }
  }
}

void gsw::external_product(GSWCiphertext gsw_enc, seal::Ciphertext bfv, size_t ct_poly_size,
                           seal::Ciphertext &res_ct) {

  const auto &context_data = context->first_context_data();
  auto &parms2 = context_data->parms();
  auto &coeff_modulus = parms2.coeff_modulus();
  size_t coeff_count = parms2.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  auto ntt_tables = context_data->small_ntt_tables();

  std::vector<std::vector<uint64_t>> decomposed_bfv;
  decomp_rlwe(bfv, decomposed_bfv);

  for (auto &poly : decomposed_bfv) {
    seal::util::CoeffIter bfv_poly_ptr(poly);
    for (int i = 0; i < coeff_mod_count; i++) {
      seal::util::ntt_negacyclic_harvey(bfv_poly_ptr + coeff_count * i, *(ntt_tables + i));
    }
  }

  // Use the delayed mod speedup
  std::vector<std::vector<uint128_t>> result(
      2, std::vector<uint128_t>(coeff_count * coeff_mod_count, 0));

  for (int k = 0; k < 2; ++k) {
    for (size_t j = 0; j < 2 * l; j++) {
      seal::util::ConstCoeffIter encrypted_gsw_ptr(gsw_enc[j].data() +
                                                   k * coeff_count * coeff_mod_count);
      seal::util::ConstCoeffIter encrypted_rlwe_ptr(decomposed_bfv[j]);
      utils::multiply_poly_acum(encrypted_rlwe_ptr, encrypted_gsw_ptr,
                                coeff_count * coeff_mod_count, result[k].data());
    }
  }

  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    auto ct_ptr = res_ct.data(poly_id);
    auto pt_ptr = result[poly_id];

    for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
      auto mod_idx = (mod_id * coeff_count);
      auto mod = static_cast<uint64_t>(coeff_modulus[mod_id].value());
      for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        ct_ptr[coeff_id + mod_idx] = static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx] % mod);
      }
    }
  }

  for (int i = 0; i < coeff_mod_count; i++) {
    seal::util::inverse_ntt_negacyclic_harvey(res_ct.data(0) + coeff_count * i, *(ntt_tables + i));
  }
  for (int i = 0; i < coeff_mod_count; i++) {
    seal::util::inverse_ntt_negacyclic_harvey(res_ct.data(1) + coeff_count * i, *(ntt_tables + i));
  }
}

void gsw::decomp_rlwe(seal::Ciphertext ct, std::vector<std::vector<uint64_t>> &output) {

  assert(output.size() == 0);
  output.reserve(2 * l);

  // Get parameters
  const uint64_t base = UINT64_C(1) << base_log2;
  const uint64_t mask = base - 1;

  const auto &context_data = context->first_context_data();
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t ct_poly_count = ct.size();
  assert(ct_poly_count == 2);

  seal::util::RNSBase *rns_base = context_data->rns_tool()->base_q();
  auto pool = seal::MemoryManager::GetPool();

  std::vector<uint64_t> data(coeff_count * coeff_mod_count);

  for (int j = 0; j < ct_poly_count; j++) {
    uint64_t *poly_ptr = ct.data(j);

    memcpy(data.data(), poly_ptr, coeff_count * coeff_mod_count * sizeof(uint64_t));
    rns_base->compose_array(data.data(), coeff_count, pool);

    for (int p = l - 1; p >= 0; p--) {
      std::vector<uint64_t> row = data;
      const int shift_amount = p * base_log2;

      for (size_t k = 0; k < coeff_count; k++) {
        auto ptr = row.data() + k * coeff_mod_count;
        seal::util::right_shift_uint(ptr, shift_amount, coeff_mod_count, ptr);
        ptr[0] &= mask;
        for (int i = 1; i < coeff_mod_count; i++) {
          ptr[i] = 0;
        }
      }

      rns_base->decompose_array(row.data(), coeff_count, pool);

      output.push_back(std::move(row));
    }
  }
  // std::cout << "SIZE " << output.size() << std::endl;
}

void gsw::query_to_gsw(std::vector<seal::Ciphertext> query, GSWCiphertext gsw_key,
                       GSWCiphertext &output) {
  assert(query.size() == l);
  assert(output.size() == 0);
  output.resize(2 * l);

  const auto &context_data = context->get_context_data(query[0].parms_id());
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();

  for (int i = 0; i < l; i++) {
    for (int j = 0; j < coeff_count * coeff_mod_count; j++) {
      output[i].push_back(query[i].data(0)[j]);
    }
    for (int j = 0; j < coeff_count * coeff_mod_count; j++) {
      output[i].push_back(query[i].data(1)[j]);
    }
  }

  for (int i = 0; i < l; i++) {
    external_product(gsw_key, query[i], coeff_count, query[i]);
    for (int j = 0; j < coeff_count * coeff_mod_count; j++) {
      output[i + l].push_back(query[i].data(0)[j]);
    }
    for (int j = 0; j < coeff_count * coeff_mod_count; j++) {
      output[i + l].push_back(query[i].data(1)[j]);
    }
  }


  gsw_ntt_negacyclic_harvey(output);
}

void gsw::encrypt_plain_to_gsw(std::vector<uint64_t> const &plaintext,
                               seal::Encryptor const &encryptor, seal::Decryptor &decryptor,
                               GSWCiphertext &output) {
  const auto &context_data = context->first_context_data();
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();

  output.clear();
  assert(plaintext.size() == coeff_count * coeff_mod_count || plaintext.size() == coeff_count);

  uint128_t pow2[coeff_mod_count][l + 1];
  for (int i = 0; i < coeff_mod_count; i++) {
    uint64_t mod = coeff_modulus[i].value();
    uint64_t pow = 1;
    for (int j = 0; j <= l; j++) {
      pow2[i][j] = pow;
      pow = (pow << base_log2) % mod;
    }
  }

  for (int poly_id = 0; poly_id <= 1; poly_id++) {
    for (int i = l - 1; i >= 0; i--) {
      seal::Ciphertext cipher;
      encryptor.encrypt_zero_symmetric(cipher);

      auto bits = (i * base_log2);
      auto ct = cipher.data(poly_id);
      for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
        auto pad = (mod_id * coeff_count);
        __uint128_t mod = coeff_modulus[mod_id].value();
        uint64_t coef = pow2[mod_id][i];
        auto pt = plaintext.data();
        if (plaintext.size() == coeff_count * coeff_mod_count) {
          pt = plaintext.data() + pad;
        }
        for (int j = 0; j < coeff_count; j++) {
          ct[j + pad] =
              static_cast<uint64_t>((ct[j + pad] + (__uint128_t(pt[j]) * coef % mod)) % mod);
        }
      }

      seal::Plaintext pt(coeff_count);
      decryptor.decrypt(cipher, pt);

      std::vector<uint64_t> row;
      for (int i = 0; i < coeff_count * coeff_mod_count; i++) {
        row.push_back(cipher.data(0)[i]);
      }
      for (int i = 0; i < coeff_count * coeff_mod_count; i++) {
        row.push_back(cipher.data(1)[i]);
      }
      output.push_back(row);
    }
  }

  gsw_ntt_negacyclic_harvey(output);
}