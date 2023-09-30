#include "tests.h"
#include "pir.h"
#include "server.h"
#include <iostream>

void run_tests() {
  PirParams pir_params(256, 2, 1500000, 5, 5);
  pir_params.print_values();

  std::cout << "Running tests..." << std::endl;
  
  test_external_product();
}

void test_external_product() {
  PirParams pir_params(256, 2, 1500000, 5, 5);
  auto context_ = seal::SEALContext(pir_params.get_seal_params());
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();
  seal::Plaintext a(poly_degree);
  seal::Plaintext b(poly_degree);
  for (int i = 0; i < 10; i++) {
    a[i] = 1;
    b[i] = 1;
  }
  seal::Ciphertext a_encrypted, b_encrypted;
  encryptor_->encrypt_symmetric(a, a_encrypted);
  encryptor_->encrypt_symmetric(b, b_encrypted);

  auto sk_ = secret_key_.data();
  auto ntt_tables = context_.key_context_data()->small_ntt_tables();
  auto key_modulus_size =
      context_.key_context_data()->parms().coeff_modulus().size();

  std::vector<uint64_t> sk_ntt(poly_degree * key_modulus_size);

  memcpy(sk_ntt.data(), sk_.data(),
         poly_degree * key_modulus_size * sizeof(uint64_t));

  RNSIter secret_key_iter(sk_ntt.data(), poly_degree);
  inverse_ntt_negacyclic_harvey(secret_key_iter, key_modulus_size, ntt_tables);
  for (int i = 0; i < 100; i++) {
    std::cout << sk_ntt[i] << ' ' << sk_ntt[i + poly_degree] << std::endl;
  }

  seal::Ciphertext cipher_result, A, B;
  evaluator_.multiply(a_encrypted, b_encrypted, cipher_result);
  seal::Plaintext result;

  auto parms = context_.get_context_data(cipher_result.parms_id())->parms();
  auto coeff_modulus = parms.coeff_modulus();

  RNSBase *base =
      context_.get_context_data(a_encrypted.parms_id())->rns_tool()->base_q();

  std::cout << base->size() << std::endl;
  std::cout << (*base)[0].value() << std::endl;
  std::cout << "Size: " << coeff_modulus.size() << std::endl;
  for (int i = 0; i < coeff_modulus.size(); i++) {
    std::cout << coeff_modulus[i].value() << std::endl;
  }
  auto pool = seal::MemoryManager::GetPool();
  auto coeff_count = parms.poly_modulus_degree();
  //
  // base.decompose_array(cipher_result.data(0), coeff_count, pool);
  for (int i = 0; i < 10; i++) {
    std::cout << cipher_result.data(0)[i] << ' '
              << cipher_result.data(0)[i + coeff_count] << std::endl;
    ;
  }

  decryptor_->decrypt(cipher_result, result);
  std::cout << result.to_string() << std::endl;
  uint64_t a2[2] = {0};
  a2[0] = cipher_result.data(0)[0];
  a2[1] = cipher_result.data(0)[coeff_count];

  std::cout << a2[0] << ' ' << a2[1] << std::endl;
  std::cout << "after compose" << std::endl;
  base->compose(a2, pool);
  std::cout << a2[0] << ' ' << a2[1] << std::endl;
  A = cipher_result;
  B = cipher_result;

  base->compose_array(cipher_result.data(0), coeff_count, pool);

  base->compose_array(A.data(0), coeff_count, pool);
  base->compose_array(B.data(0), coeff_count, pool);

  for (int i = 0; i < 10; i++) {
    std::cout << cipher_result.data(0)[i * 2] << ' '
              << cipher_result.data(0)[i * 2 + 1] << std::endl;
    right_shift_uint(cipher_result.data(0) + i * 2, 1, 2,
                     cipher_result.data(0) + i * 2);
    std::cout << cipher_result.data(0)[i * 2] << ' '
              << cipher_result.data(0)[i * 2 + 1] << std::endl;
  }
  for (int i = 0; i < coeff_count; i++) {
    A.data(0)[i * 2] = 0;
    B.data(0)[i * 2 + 1] = 0;
  }

  base->decompose_array(cipher_result.data(0), coeff_count, pool);

  base->decompose_array(A.data(0), coeff_count, pool);
  base->decompose_array(B.data(0), coeff_count, pool);
  std::cout << "after decompose" << std::endl;

  for (int i = 0; i < 10; i++) {
    std::cout << cipher_result.data(0)[i] << ' '
              << cipher_result.data(0)[i + coeff_count] << std::endl;

    std::cout << A.data(0)[i] << ' ' << A.data(0)[i + coeff_count] << std::endl;

    std::cout << B.data(0)[i] << ' ' << B.data(0)[i + coeff_count] << std::endl
              << std::endl;
  }

  decryptor_->decrypt(cipher_result, result);
  std::cout << result.to_string() << std::endl;
  // context_->get_context_data(cipher_result.parms_id())->coeff
}

void test_pir() {
  PirParams pir_params(256, 2, 1500000, 5, 5);
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
    entry.push_back(255);
    entry.push_back(173);
    entry.push_back(19);
    entry.push_back(26);
    entry.push_back(114);
    // entry.push_back(183);
  }
  server.set_database(data);
  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;

  server.set_client_galois_key(client_id, client.create_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  std::cout << "Client registered" << std::endl;

  // client.test_external_product();
  int id = 1350000;
  auto result = server.make_query(client_id, client.generate_query(id));

  std::cout << "Result: " << std::endl;
  auto decrypted_result = client.decrypt_result(result);
#ifdef _DEBUG
  for (auto &res : decrypted_result) {
    // std::cout << res.to_string() << std::endl;
  }
#endif
  print_entry(client.get_entry_from_plaintext(id, decrypted_result[0]));

#ifdef _BENCHMARK
  std::cout << "Noise budget remaining: "
            << client.get_decryptor()->invariant_noise_budget(result[0])
            << " bits" << std::endl;

  auto query = client.generate_query(5);
  auto start_time = std::chrono::high_resolution_clock::now();
  server.make_query_regular_mod(client_id, query);
  auto end_time = std::chrono::high_resolution_clock::now();
  auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  std::cout << "No delayed mod: " << elapsed_time.count() << " ms" << std::endl;

  start_time = std::chrono::high_resolution_clock::now();
  server.make_query_delayed_mod(client_id, query);
  end_time = std::chrono::high_resolution_clock::now();
  elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  std::cout << "Delayed mod: " << elapsed_time.count() << " ms" << std::endl;

  std::cout << std::endl;
#endif
}