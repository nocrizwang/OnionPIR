#include "test_query.h"
#include "utils.h"
#include "seal/util/uintarithmod.h"

#define EXPERIMENT_ITER 1


void run_query_test() {
  PirTest test;
  // test.gen_and_expand();
  test.enc_then_add();
}

std::unique_ptr<PirServer> PirTest::prepare_server(bool init_db, PirParams &pir_params, PirClient &client, const int client_id) {
  std::unique_ptr<PirServer> server = std::make_unique<PirServer>(pir_params);
  server->decryptor_ = client.get_decryptor();
  server->set_client_galois_key(client_id, client.create_galois_keys());
  server->set_client_gsw_key(client_id, client.generate_gsw_from_key());
  if (init_db) {
    server->gen_data();
  }
  return server;
}


void PirTest::gen_and_expand() {
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  PirClient client(pir_params);
  srand(time(0));
  const int client_id = rand();
  std::unique_ptr<PirServer> server = prepare_server(false, pir_params, client, client_id);

  // ======================== Start generating the query
  size_t entry_idx = rand() % pir_params.get_num_entries();
  DEBUG_PRINT("Client ID: " << client_id << " Entry index: " << entry_idx);
  PirQuery query = client.generate_query(entry_idx);  // a single BFV ciphertext


  // ======================== server receives the query and expand it
  auto expanded_query = server->get_expanded_queries(query, client_id);  // a vector of BFV ciphertexts
  std::vector<uint64_t> dims = server->get_dims();

  // ======================== client decrypts the query vector and interprets the result
  std::vector<seal::Plaintext> decrypted_query = client.decrypt_result(expanded_query);

  // check the first dimension is the first dims[0] plaintext in decrypted_query
  for (size_t i = 0; i < dims[0]; i++) {
    if (decrypted_query[i].is_zero() == false) {
      DEBUG_PRINT("Dimension 0[" << i << "]: " << decrypted_query[i].to_string());
    }
  }
  int ptr = dims[0];
  size_t gsw_l = pir_params.get_l();
  // for the rest dimensions, we read l plaintexts for each "GSW" plaintext, and reconstruct the using these l values.
  for (size_t dim_idx = 1; dim_idx < dims.size(); ++dim_idx) {
    std::cout << "Dimension " << dim_idx << ": ";
    for (int k = 0; k < gsw_l; k++) {
      std::cout << "0x" << decrypted_query[ptr + k].to_string() << " ";
    }
    std::cout << std::endl;
    ptr += gsw_l;
  }


}

void PirTest::enc_then_add() {
  DEBUG_PRINT("Running: " << __FUNCTION__);

  // ======================== Initialize the client and server
  PirParams pir_params{DB_SZ, NUM_DIM, NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  PirClient client(pir_params);
  srand(time(0));
  const int client_id = rand();
  std::unique_ptr<PirServer> server = prepare_server(false, pir_params, client, client_id);

  // ======================== we try a simpler version of the client generate_query
  size_t coeff_count = pir_params.get_seal_params().poly_modulus_degree();
  seal::Plaintext plain_query{coeff_count};

  PirQuery query;
  client.encryptor_->encrypt_symmetric(plain_query, query);

  auto context_data = client.context_->first_context_data();
  auto coeff_modulus = context_data->parms().coeff_modulus();
  auto coeff_mod_count = coeff_modulus.size();  // 2
  auto base_log2 = pir_params.get_base_log2();
  auto l = pir_params.get_l();

  uint128_t pow2[coeff_mod_count][l];
  for (int i = 0; i < coeff_mod_count; i++) {
    uint128_t mod = coeff_modulus[i].value();
    uint128_t pow = 1;
    for (int j = 0; j < l; j++) { 
      pow2[i][j] = pow;
      pow = (pow << base_log2) % mod; // multiply by B and take mod every time
    }
  }

  auto pt = query.data(0);
  for (int j = 0; j < l; ++j) {
    for (int k = 0; k < coeff_mod_count; ++k) {
      auto pt_offset = k * coeff_count;
      uint128_t mod = coeff_modulus[k].value();
      uint128_t coef = pow2[k][j]; // no inv here.
      pt[j + pt_offset] = (pt[j + pt_offset] + coef) % mod;
    }
  }

  // ======================== Decrypt the query and interpret the result
  std::vector<seal::Plaintext> decrypted_query = client.decrypt_result({query});
  std::cout << "\n Decrypted in hex: " << decrypted_query[0].to_string() << std::endl;
  
}