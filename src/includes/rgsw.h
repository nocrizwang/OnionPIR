// Trying to implement the RGSW encryption scheme that only handles RGSW(0) and RGSW(1).
// We hope to use a simpler implementation to simplify our code.
// This is because we only want to use RGSW(0) or RGSW(1).
// In this case, we will try to use std::vector<seal::Ciphertext> as the RGSW ciphertext.

#pragma once

#include "seal/seal.h"
#include "pir.h"
#include "external_prod.h"

typedef std::vector<seal::Ciphertext> RGSWCtxt;

class RGSWEval {
  public:

    // Construct the gadget value based on params_
    std::vector<uint64_t> gen_gadget(const PirParams& params);

    // return RGSW(1)
    RGSWCtxt RGSW_one(const PirParams &params, const seal::Encryptor *encryptor_, const GSWCiphertext &neg_secret_key);


};
