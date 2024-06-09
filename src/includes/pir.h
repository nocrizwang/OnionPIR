#pragma once

#include "database_constants.h"
#include "external_prod.h"
#include "seal/seal.h"
#include <stdexcept>
#include <vector>


#define DEBUG_PRINT(s) std::cout << s << std::endl;  // print for debug
// #define DEBUG_PRINT(s) ; // do nothing

using namespace seal::util;
using namespace seal;

// Each entry is a vector of bytes
typedef std::vector<uint8_t> Entry;
typedef Ciphertext PirQuery;

class PirParams {
public:
  /*!
      PirParams constructor.
      @param DBSize - Number of plaintexts in database
      @param ndim - Number of database dimensions
      @param num_entries - Number of entries in database
      @param entry_size - Size of each entry in bytes
      @param l - Parameter l for GSW scheme
      */
  PirParams(uint64_t DBSize, uint64_t ndim, uint64_t num_entries, uint64_t entry_size, uint64_t l,
            uint64_t l_key)
      : DBSize_(DBSize), seal_params_(seal::EncryptionParameters(seal::scheme_type::bfv)),
        num_entries_(num_entries), entry_size_(entry_size), l_(l) {
    
    // Since all dimensions are fixed to 2 except the first one. We calculate the first dimension here.
    uint64_t first_dim = DBSize >> (ndim - 1);
    if (first_dim < 128) {
      throw std::invalid_argument("Size of first dimension is too small");
    }
    if ((first_dim & (first_dim - 1))) {
      throw std::invalid_argument("Size of database is not a power of 2");
    }

    // First dimension must be a power of 2.
    // After experiment, when first_dim is 128, the performance is the best.
    dims_.push_back(first_dim); // ?can we use emplace_back here?
    for (int i = 1; i < ndim; i++) {
      dims_.push_back(2); // ! All other dimensions are fixed to 2. But why not 4 here? according to paper?
    }
    seal_params_.set_poly_modulus_degree(DatabaseConstants::PolyDegree);

    if (DatabaseConstants::PolyDegree == 8192) {
      seal_params_.set_coeff_modulus(
          CoeffModulus::Create(DatabaseConstants::PolyDegree, {60, 60, 60}));
    } else {
      seal_params_.set_coeff_modulus(CoeffModulus::BFVDefault(DatabaseConstants::PolyDegree));
    }

    // seal_params_.set_coeff_modulus(CoeffModulus::Create(DatabaseConstants::PolyDegree,
    // {55, 50, 50, 60}));
    // seal_params_.set_plain_modulus(
    //     PlainModulus::Batching(DatabaseConstants::PolyDegree,
    //     DatabaseConstants::PlaintextModBits));
    seal_params_.set_plain_modulus(DatabaseConstants::PlaintextMod);

    // ! Question: What is the "plaintext" here? Why it is possible to have multiple entries in a plaintext?
    // DEBUG_PRINT("get_num_entries_per_plaintext() = " << get_num_entries_per_plaintext());

    // The first part calculates the number of entries that this database can hold in total. (limits)
    // num_entries is the number of useful entries that the user can use in the database.
    if (DBSize_ * get_num_entries_per_plaintext() < num_entries) {
      throw std::invalid_argument("Number of entries in database is too large");
    }


    // ! what is this "modulus" and "bits" used for? Meaning?
    auto modulus = seal_params_.coeff_modulus();
    int bits = 0;
    for (int i = 0; i < modulus.size() - 1; i++) {
      bits += modulus[i].bit_count();
    }

    // ! what is this used for? It seems that later in client.cpp, PirClient::generate_query(std::uint64_t entry_index)
    // ! uses this in the "pow". But if this base_log2_ means "log_2 {B}", then pow << base_log2_ means pow * B.
    base_log2_ = (bits + l - 1) / l;

    // Set up parameters for GSW in external_prod.h
    data_gsw.l = l;
    data_gsw.base_log2 = base_log2_;
    data_gsw.context = new seal::SEALContext(seal_params_);

    // If l_key == l, then these two are exactly the same.
    key_gsw.l = l_key;
    key_gsw.base_log2 = (bits + l_key - 1) / l_key;   // same calculation method 
    key_gsw.context = data_gsw.context;
    
  }
  seal::EncryptionParameters get_seal_params() const;
  void print_values();
  uint64_t get_DBSize() const;
  std::vector<uint64_t> get_dims() const;
  // Calculates the number of entries that each plaintext can contain, aligning
  // the end of an entry to the end of a plaintext.
  size_t get_num_entries_per_plaintext() const;
  size_t get_num_bits_per_coeff() const;
  // Calculates the number of bytes of data each plaintext contains, after
  // aligning the end of an entry to the end of a plaintext.
  size_t get_num_bits_per_plaintext() const;
  size_t get_num_entries() const;
  size_t get_entry_size() const;
  uint64_t get_l() const;
  uint64_t get_base_log2() const;

private:
  uint64_t DBSize_;            // number of plaintexts in the database
  uint64_t l_;                 // l for GSW
  uint64_t base_log2_;         // log of base for GSW
  std::vector<uint64_t> dims_; // Number of dimensions
  size_t num_entries_;         // Number of entries in database
  size_t entry_size_;          // Size of single entry in bytes
  seal::EncryptionParameters seal_params_;
};

void print_entry(Entry entry);