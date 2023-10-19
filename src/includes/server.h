#pragma once

#include "client.h"
#include "external_prod.h"
#include "pir.h"
#include "seal/seal.h"

typedef std::vector<seal::Plaintext> Database;

class PirServer {
public:
  PirServer(const PirParams &pir_params);
  /*!
    Replaces the database with random data
  */
  void gen_data();
  /*!
    Sets the database to a new database
  */
  void set_database(std::vector<Entry> &new_db);
  std::vector<seal::Ciphertext> make_query(uint32_t client_id, PirQuery &&query);
  std::vector<seal::Ciphertext> make_query_delayed_mod(uint32_t client_id, PirQuery query);
  std::vector<seal::Ciphertext> make_query_regular_mod(uint32_t client_id, PirQuery query);
  std::vector<seal::Ciphertext> evaluate_gsw_product(std::vector<seal::Ciphertext> &result,
                                                     std::vector<GSWCiphertext> &selection_vector);
  void set_client_galois_key(uint32_t client_id, seal::GaloisKeys client_key);
  void set_client_gsw_key(uint32_t client_id, GSWCiphertext &&gsw_key);

  seal::Decryptor *decryptor_;

private:
  uint64_t DBSize_;
  seal::SEALContext context_;
  seal::Evaluator evaluator_;
  std::vector<uint64_t> dims_;
  std::map<uint32_t, seal::GaloisKeys> client_galois_keys_;
  std::map<uint32_t, GSWCiphertext> client_gsw_keys_;
  Database db_;
  PirParams pir_params_;

  /*!
    Expands the first query ciphertext into a selection vector of ciphertexts
    where the ith ciphertext encodes the ith bit of the first query ciphertext.
  */
  std::vector<seal::Ciphertext> expand_query(uint32_t client_id, seal::Ciphertext ciphertext);
  /*!
    Performs a cross product between the first selection vector and the
    database.
  */
  std::vector<seal::Ciphertext> evaluate_first_dim(std::vector<seal::Ciphertext> &selection_vector);
  std::vector<seal::Ciphertext>
  evaluate_first_dim_delayed_mod(std::vector<seal::Ciphertext> &selection_vector);

  /*!
    Transforms the plaintexts in the database into their NTT representation.
    This speeds up computation but takes up more memory.
  */
  void preprocess_ntt();
};