#pragma once
#include "seal/seal.h"
#include <vector>

// A GSWCiphertext is a flattened 2lx2 matrix of polynomials
typedef std::vector<std::vector<uint64_t>> GSWCiphertext;

/*!
  Computes the external product between a GSW ciphertext and a decomposed BFV
  ciphertext.
  @param gsw_enc -GSW Ciphertext, should only encrypt 0 or 1 to prevent large
  noise growth
  @param rlwe_expansion - decomposed vector of BFV ciphertext
  @param context - SEAL context
  @param l - number of GSW rows
  @param ct_poly_size - number of ciphertext polynomials
  @param res_ct - output ciphertext
*/
void external_product(GSWCiphertext &gsw_enc,
                      std::vector<uint64_t *> &decomposed_bfv,
                      std::shared_ptr<seal::SEALContext> &context, int l,
                      size_t ct_poly_size, seal::Ciphertext &res_ct);

/*!
  Performs a gadget decomposition of a size 2 BFV ciphertext into 2 sets of rows
  of l polynomials (the 2 sets are concatenated into a single vector of
  vectors). Each polynomial coefficient encodes the value congruent to the
  original ciphertext coefficient modulus the value of base^(l-row).
  @param ct - input BFV ciphertext. Should be of size 2.
  @param l - number of GSW rows
  @param context - SEAL context
  @param output - output to store the decomposed ciphertext as a vector of
  vectors of polynomial coefficients
  @param base_log2 - value of log2(GSW base) (base must be a power of 2)
  @param pool - SEAL memory pool
*/
void decomp_rlwe(seal::Ciphertext ct, const uint64_t l,
                 std::shared_ptr<seal::SEALContext> context,
                 std::vector<std::vector<uint64_t>> output,
                 const uint64_t base_log2);

/*!
  Generates a GSW ciphertext from a BFV ciphertext query.

  @param query - input BFV ciphertext. Should be of size l * 2.
  @param l - number of GSW rows
  @param context_data - SEAL context data
  @param output - output to store the GSW ciphertext as a vector of vectors of
  polynomial coefficients
  @param base_log2 - value of log2(GSW base) (base must be a power of 2)
*/
void query_to_gsw(std::vector<seal::Ciphertext> query, const uint64_t l,
                  std::shared_ptr<seal::SEALContext::ContextData> context_data,
                  GSWCiphertext &output, const uint64_t base_log2);
