#pragma once
#include "seal/seal.h"
#include <vector>

// A GSWCiphertext is a flattened 2lx2 matrix of polynomials
typedef std::vector<std::vector<uint64_t>> GSWCiphertext;

class GSWEval {
public:
  /*!
    Computes the external product between a GSW ciphertext and a decomposed BFV
    ciphertext.
    @param gsw_enc -GSW Ciphertext, should only encrypt 0 or 1 to prevent large
    noise growth
    @param rlwe_expansion - decomposed vector of BFV ciphertext
    @param ct_poly_size - number of ciphertext polynomials
    @param res_ct - output ciphertext
  */

  void external_product(GSWCiphertext const &gsw_enc, seal::Ciphertext const &bfv,
                        size_t ct_poly_size, seal::Ciphertext &res_ct);

  /*!
    Performs a gadget decomposition of a size 2 BFV ciphertext into 2 sets of
    rows of l polynomials (the 2 sets are concatenated into a single vector of
    vectors). Each polynomial coefficient encodes the value congruent to the
    original ciphertext coefficient modulus the value of base^(l-row).
    @param ct - input BFV ciphertext. Should be of size 2.
    @param output - output to store the decomposed ciphertext as a vector of
    vectors of polynomial coefficients
    @param pool - SEAL memory pool
  */
  void decomp_rlwe(seal::Ciphertext const &ct, std::vector<std::vector<uint64_t>> &output);

  /*!
    Generates a GSW ciphertext from a BFV ciphertext query.

    @param query - input BFV ciphertext. Should be of size l * 2.
    @param gsw_key - GSW encryption of -s
    @param output - output to store the GSW ciphertext as a vector of vectors of
    polynomial coefficients
  */
  void query_to_gsw(std::vector<seal::Ciphertext> query, GSWCiphertext gsw_key,
                    GSWCiphertext &output);

  void encrypt_plain_to_gsw(std::vector<uint64_t> const &plaintext,
                            seal::Encryptor const &encryptor, seal::Decryptor &decryptor,
                            GSWCiphertext &output);

  void gsw_ntt_negacyclic_harvey(GSWCiphertext &gsw);

  void cyphertext_inverse_ntt(seal::Ciphertext &ct);

  uint64_t l;
  uint64_t base_log2;
  seal::SEALContext const *context;
};

extern GSWEval data_gsw, key_gsw;