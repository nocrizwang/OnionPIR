#include "tests.h"
#include "external_prod.h"
#include "pir.h"
#include "seal/util/scalingvariant.h"
#include "server.h"
#include "utils.h"
#include <iostream>
#include <random>

void run_tests() {
  PirParams pir_params(256, 2, 20000, 5, 15, 15);
  // pir_params.print_values();

  std::cout << "Running tests..." << std::endl;

  // bfv_example();
  // test_external_product();
  test_pir();
  // test_keyword_pir();
}

void bfv_example() {
  PirParams pir_params(256, 2, 20000, 5, 5, 5);
  auto context_ = seal::SEALContext(pir_params.get_seal_params());
  auto evaluator_ = seal::Evaluator(context_);
  auto keygen_ = seal::KeyGenerator(context_);
  auto secret_key_ = keygen_.secret_key();
  auto encryptor_ = new seal::Encryptor(context_, secret_key_);
  auto decryptor_ = new seal::Decryptor(context_, secret_key_);

  uint64_t poly_degree = pir_params.get_seal_params().poly_modulus_degree();
  std::cout << "Size f: " << context_.key_context_data()->parms().coeff_modulus().size()
            << std::endl;
  std::cout << "Size f: " << context_.first_context_data()->parms().coeff_modulus().size()
            << std::endl;
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
  PirParams pir_params(256, 2, 20000, 5, 15, 15);
  pir_params.print_values();
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

  a[0] = 123;
  a[1] = 221;
  a[2] = 69;
  b[0] = 1;

  encryptor_.encrypt_symmetric(a, a_encrypted);

  std::cout << "Noise budget before: " << decryptor_.invariant_noise_budget(a_encrypted)
            << std::endl;
  GSWCiphertext b_gsw;
  data_gsw.encrypt_plain_to_gsw(b, encryptor_, decryptor_, b_gsw);

  debug(a_encrypted.data(0), "AENC[0]", coeff_count);
  debug(a_encrypted.data(1), "AENC[1]", coeff_count);

  for (int i = 0; i < 1; i++) {
    data_gsw.external_product(b_gsw, a_encrypted, coeff_count, a_encrypted);
    data_gsw.cyphertext_inverse_ntt(a_encrypted);
    decryptor_.decrypt(a_encrypted, result);
    std::cout << "Noise budget after: " << decryptor_.invariant_noise_budget(a_encrypted)
              << std::endl;
  }

  std::cout << result.to_string() << std::endl;
  std::cout << result.nonzero_coeff_count() << std::endl;
}

Entry generate_entry(int id, int len) {
  Entry entry;
  std::mt19937 rng(id);
  for (int i = 0; i < len; i++) {
    entry.push_back(rng() % 256);
  }
  return entry;
}

Entry generate_entry_with_id(uint64_t id, int len) {
  Entry entry;
  std::mt19937 rng(id);

  for (int i = 0; i < 8; i++) {
    entry.push_back((id >> (8 * i)) % 256);
  }

  for (int i = 0; i < len - 8; i++) {
    entry.push_back(rng() % 256);
  }
  return entry;
}

void test_pir() {
  // setting parameters for PIR scheme
  // - Database size = 2^15
  // - Number of dimensions = 8
  // - Number of entries = 2^15
  // - Entry size = 12000 bytes
  // - l = 9  (parameter for GSW scheme)
  // - l_key = 9 
  PirParams pir_params(1 << 15, 8, 1 << 15, 12000, 9, 9);
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

  for (int i = 0; i < pir_params.get_num_entries(); i++) {
    data[i] = generate_entry(i, pir_params.get_entry_size());
  }

  server.set_database(data);
  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server.decryptor_ = client.get_decryptor();
  server.set_client_galois_key(client_id, client.create_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  std::cout << "Client registered" << std::endl;

  for (int i = 0; i < 10; i++) {
    int id = rand() % pir_params.get_num_entries();

    auto start_time0 = std::chrono::high_resolution_clock::now();
    auto query = client.generate_query(id);
    auto start_time = std::chrono::high_resolution_clock::now();
    auto result = server.make_query(client_id, std::move(query));
    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_time =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    std::cout << "Server Time: " << elapsed_time.count() << " ms" << std::endl;

    std::cout << "Result: " << std::endl;
    std::cout << client.get_decryptor()->invariant_noise_budget(result[0]) << std::endl;
    auto decrypted_result = client.decrypt_result(result);

    // std::cout << "Decrypted result: " << decrypted_result[0].to_string() << std::endl;
    Entry entry = client.get_entry_from_plaintext(id, decrypted_result[0]);
    auto end_time0 = std::chrono::high_resolution_clock::now();

    auto elapsed_time0 =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_time0 - start_time0);
    std::cout << "Client Time: " << elapsed_time0.count() - elapsed_time.count() << " ms"
              << std::endl;
    if (entry == data[id]) {
      std::cout << "Success!" << std::endl;
    } else {
      std::cout << "Failure!" << std::endl;

      std::cout << "Result:\t";
      print_entry(entry);
      std::cout << "Data:\t";
      print_entry(data[id]);
    }
  }
}

void test_keyword_pir() {
  int table_size = 1 << 15;
  PirParams pir_params(table_size, 8, table_size, 12000, 9, 9);
  pir_params.print_values();
  const int client_id = 0;
  PirServer server1(pir_params), server2(pir_params);

  int num_entries = table_size;
  std::vector<uint64_t> keywords;
  std::vector<Entry> data(num_entries);

  std::vector<uint64_t> t1(table_size), t2(table_size);
  std::vector<Entry> cuckoo1(table_size), cuckoo2(table_size);

  std::mt19937_64 rng;
  for (int i = 0; i < num_entries; i++) {
    uint64_t keyword = rng();
    keywords.push_back(keyword);
    data[i] = generate_entry_with_id(keyword, pir_params.get_entry_size());
  }

  std::hash<uint64_t> hasher;
  uint64_t seed1 = rng(), seed2 = rng();
  table_size -= 1;
  while (1) {
    std::cout << "attempt hash" << std::endl;
    for (int i = 0; i < table_size; i++) {
      t1[i] = t2[i] = 0;
    }
    seed1 = rng();
    seed2 = rng();
    for (int i = 0; i < num_entries; i++) {
      uint64_t x = keywords[i];
      bool success = false;
      for (int j = 0; j < 100; j++) {
        if (t1[hasher(x ^ seed1) % table_size] == 0) {
          t1[hasher(x ^ seed1) % table_size] = x;
          success = true;
          break;
        }
        std::swap(x, t1[hasher(x ^ seed1) % table_size]);
        if (t2[hasher(x ^ seed2) % table_size] == 0) {
          t2[hasher(x ^ seed2) % table_size] = x;
          success = true;
          break;
        }
        std::swap(x, t2[hasher(x ^ seed2) % table_size]);
      }
      if (!success) {
        goto nxt;
      }
    }
    break;
  nxt:;
  }

  for (int i = 0; i < num_entries; i++) {
    uint64_t x = keywords[i];
    if (t1[hasher(x ^ seed1) % table_size] == x) {
      cuckoo1[hasher(x ^ seed1) % table_size] = data[i];
    } else {
      cuckoo2[hasher(x ^ seed2) % table_size] = data[i];
    }
  }

  // for (int i = 0; i < num_entries; i++) {
  //   cuckoo1[i].resize(pir_params.get_entry_size(), 0);
  //   cuckoo2[i].resize(pir_params.get_entry_size(), 0);
  // }

  server1.set_database(cuckoo1);
  server2.set_database(cuckoo2);

  std::cout << "DB set" << std::endl;

  PirClient client(pir_params);
  std::cout << "Client initialized" << std::endl;
  server1.decryptor_ = client.get_decryptor();
  server1.set_client_galois_key(client_id, client.create_galois_keys());
  server1.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  server2.decryptor_ = client.get_decryptor();
  server2.set_client_galois_key(client_id, client.create_galois_keys());
  server2.set_client_gsw_key(client_id, client.generate_gsw_from_key());

  std::cout << "Client registered" << std::endl;

  for (int i = 0; i < 1; i++) {
    int id = rng() % num_entries;
    auto query_id1 = hasher(keywords[id] ^ seed1) % table_size;
    auto query_id2 = hasher(keywords[id] ^ seed2) % table_size;
    auto query = client.generate_query(query_id1);
    auto result = server1.make_query(client_id, std::move(query));

    auto query2 = client.generate_query(query_id2);
    auto result2 = server2.make_query(client_id, std::move(query2));

    std::cout << "Result: " << std::endl;
    std::cout << client.get_decryptor()->invariant_noise_budget(result[0]) << std::endl;

    Entry entry1 = client.get_entry_from_plaintext(id, client.decrypt_result(result)[0]);
    Entry entry2 = client.get_entry_from_plaintext(id, client.decrypt_result(result2)[0]);

    auto end_time0 = std::chrono::high_resolution_clock::now();

    if (entry1 == data[id]) {
      std::cout << "Success with first query" << std::endl;
    } else if (entry2 == data[id]) {
      std::cout << "Success with second query" << std::endl;
    } else {
      std::cout << "Failure!" << std::endl;

      std::cout << "Result:\t";
      print_entry(entry1);
      print_entry(entry2);
      std::cout << "Data:\t";
      print_entry(data[id]);
    }
  }
}