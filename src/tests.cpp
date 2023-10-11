#include "tests.h"
#include "external_prod.h"
#include "pir.h"
#include "seal/util/scalingvariant.h"
#include "server.h"
#include "utils.h"
#include <iostream>

void run_tests() {
  PirParams pir_params(256, 2, 200000, 5, 15);
  // pir_params.print_values();

  std::cout << "Running tests..." << std::endl;

  // bfv_example();
  // test_external_product();
  test_pir();
}

void bfv_example() {
  PirParams pir_params(256, 2, 200000, 5, 5);
  auto context_ = seal::SEALContext(pir_params.get_seal_params());
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();
  seal::Plaintext a(poly_degree), b(poly_degree), result;
  a[0] = 1;
  a[1] = 9;
  b[0] = 3;
  b[1] = 6;
  seal::Ciphertext a_encrypted, b_encrypted, cipher_result;
  encryptor_->encrypt_symmetric(a, a_encrypted);
  encryptor_->encrypt_symmetric(b, b_encrypted);
  evaluator_.multiply(a_encrypted, b_encrypted, cipher_result);
  decryptor_->decrypt(cipher_result, result);
  std::cout << result.to_string() << std::endl;
}

void test_external_product() {
  PirParams pir_params(256, 2, 200000, 5, 15);
  auto parms = pir_params.get_seal_params();
  auto context_ = seal::SEALContext(parms);
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = seal::Encryptor(context_, secret_key_);
  auto decryptor_ = seal::Decryptor(context_, secret_key_);
  size_t coeff_count = parms.poly_modulus_degree();
  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();
  seal::Plaintext a(poly_degree), result;
  size_t plain_coeff_count = a.coeff_count();
  seal::Ciphertext a_encrypted(context_), cipher_result(context_);
  auto &context_data = *context_.first_context_data();
  std::vector<uint64_t> b(poly_degree);

  a[0] = 1;
  a[1] = 2;
  a[2] = 6;
  b[0] = 1;
  b[1] = 2;
  b[2] = 6;

  encryptor_.encrypt_symmetric(a, a_encrypted);
  GSWCiphertext b_gsw;
  gsw::encrypt_plain_to_gsw(b, encryptor_, decryptor_, b_gsw);

  debug(a_encrypted.data(0), "AENC[0]", coeff_count);
  debug(a_encrypted.data(1), "AENC[1]", coeff_count);

  gsw::external_product(b_gsw, a_encrypted, coeff_count, a_encrypted);

  debug(a_encrypted.data(0), "RESULT[0]", coeff_count);
  debug(a_encrypted.data(1), "RESULT[1]", coeff_count);
  decryptor_.decrypt(a_encrypted, result);
  std::cout << "Noise budget: " << decryptor_.invariant_noise_budget(a_encrypted) << std::endl;
  std::cout << result.to_string() << std::endl;
  std::cout << result.nonzero_coeff_count() << std::endl;
}

void test_pir() {
  PirParams pir_params(256, 2, 200000, 5, 15);
  pir_params.print_values();
  const int client_id = 0;
  PirServer server(pir_params);
  // server.gen_data();

#ifdef _DEBUG
  std::cout << "===== Debug build =====" << std::endl;
#endif
#ifdef _BENCHMARK
  std::cout << " ===== Benchmark build =====" << std::endl;
#endif

  std::vector<Entry> data(pir_params.get_num_entries());
  for (auto &entry : data) {
    entry.push_back(4);
    entry.push_back(8);
    entry.push_back(12);
    entry.push_back(16);
    entry.push_back(20);
  }
  server.set_database(data);
  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;

  server.set_client_galois_key(client_id, client.create_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  std::cout << "Client registered" << std::endl;

  int id = 135005;
  auto result = server.make_query(client_id, client.generate_query(id));

  std::cout << "Result: " << std::endl;
  std::cout << client.get_decryptor()->invariant_noise_budget(result[0]) << std::endl;
  auto decrypted_result = client.decrypt_result(result);
#ifdef _DEBUG
  for (auto &res : decrypted_result) {
    // std::cout << res.to_string() << std::endl;
  }
#endif
  print_entry(client.get_entry_from_plaintext(id, decrypted_result[0]));

#ifdef _BENCHMARK
  std::cout << "Noise budget remaining: "
            << client.get_decryptor()->invariant_noise_budget(result[0]) << " bits" << std::endl;

  auto query = client.generate_query(5);
  auto start_time = std::chrono::high_resolution_clock::now();
  server.make_query_regular_mod(client_id, query);
  auto end_time = std::chrono::high_resolution_clock::now();
  auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  std::cout << "No delayed mod: " << elapsed_time.count() << " ms" << std::endl;

  start_time = std::chrono::high_resolution_clock::now();
  server.make_query_delayed_mod(client_id, query);
  end_time = std::chrono::high_resolution_clock::now();
  elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
  std::cout << "Delayed mod: " << elapsed_time.count() << " ms" << std::endl;

  std::cout << std::endl;
#endif
}

// seal::Plaintext a(coeff_count), result;
// size_t plain_coeff_count = a.coeff_count();
// seal::Ciphertext a_encrypted, cipher_result;
// a[0] = 1;
// encryptor_->encrypt_symmetric(a, a_encrypted);

// gsw::external_product(gsw_enc, a_encrypted, coeff_count, a_encrypted);

// decryptor_->decrypt(a_encrypted, result);
// std::cout << "Noise budget: "
//           << decryptor_->invariant_noise_budget(a_encrypted) << std::endl;
// std::cout << result.to_string().substr(0, 500) << std::endl;
// std::cout << result.nonzero_coeff_count() << std::endl;

// encryptor_->encrypt_zero_symmetric(a_encrypted);

// seal::util::multiply_add_plain_with_scaling_variant(
//     a, *(context_->first_context_data()),
//     RNSIter(a_encrypted.data(1), coeff_count));

// decryptor_->decrypt(a_encrypted, result);
// std::cout << "Noise budget: "
//           << decryptor_->invariant_noise_budget(a_encrypted) << std::endl;
// std::cout << result.to_string().substr(0, 500) << std::endl;
// std::cout << result.nonzero_coeff_count() << std::endl;
// exit(0);