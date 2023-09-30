#include "pir.h"
#include "server.h"
#include <chrono>
#include <iostream>

namespace gsw {
uint64_t l;
uint64_t base_log2;
} // namespace gsw

int main() {
  // PirParams pir_params(1048576, 8, 1000000, 3);
  PirParams pir_params(256, 2, 1500000, 5, 5);
  const int client_id = 0;
  pir_params.print_values();

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

  //client.test_external_product();
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
  return 0;
}

// Check timing and noise values
// Move on to GSW
// ORAM Paper for GSW details