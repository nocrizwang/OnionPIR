#include "test_query.h"

#define EXPERIMENT_ITER 1


void run_query_test() {
  DEBUG_PRINT("Running tests");
  PRINT_BAR;

  // set up parameters
  PirParams pir_params{DB_SZ, NUM_DIM,NUM_ENTRIES, ENTRY_SZ, GSW_L, GSW_L_KEY};
  pir_params.print_values();

  // Initialize the client
  srand(time(0));
  const int client_id = rand();
  PirClient client(pir_params);

  // set up server
  PirServer server(pir_params);
  server.decryptor_ = client.get_decryptor();
  server.set_client_galois_key(client_id, client.create_galois_keys());
  server.set_client_gsw_key(client_id, client.generate_gsw_from_key());


  // ======================== Start generating the query
  size_t entry_idx = rand() % pir_params.get_num_entries();
  DEBUG_PRINT("Client ID: " << client_id << " Entry index: " << entry_idx);
  PirQuery query = client.generate_query(entry_idx);  // a single BFV ciphertext


  // ======================== server receives the query and expand it
  auto expanded_query = server.get_expanded_queries(query, client_id);  // a vector of BFV ciphertexts
  std::vector<uint64_t> dims = server.get_dims();

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