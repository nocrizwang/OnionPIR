#include <rgsw.h>


std::vector<uint64_t> RGSWEval::gen_gadget(const PirParams& params) {
  // Generate the gadget value
  uint64_t l = params.get_l();
  auto plain_modulus = params.get_seal_params().plain_modulus().value();
  auto base_log2 = params.get_base_log2();
  std::vector<uint64_t> gadget(l); 

  uint64_t curr_exp = 1;
  for (uint64_t i = 0; i < l; i++) {
    gadget[i] = curr_exp;
    curr_exp = (curr_exp << base_log2) % plain_modulus;
  }

  return gadget;
}


RGSWCtxt RGSWEval::RGSW_one(const PirParams &params, const seal::Encryptor *encryptor_, const GSWCiphertext &neg_secret_key) {
  std::vector<uint64_t> gadget = gen_gadget(params);  
  auto l = params.get_l();
  RGSWCtxt rgsw(l * 2);
  auto plain_modulus = params.get_seal_params().plain_modulus().value();
  auto coeff_count = params.get_seal_params().poly_modulus_degree();

  // calculate value * gadget[i] % plain_modulus
  for (uint64_t i = 0; i < l; i++) {
    seal::Plaintext gadge_elem(std::to_string(gadget[i]));
    DEBUG_PRINT("pt: " << gadge_elem.to_string());
    
    seal::Ciphertext lower;
    encryptor_->encrypt_symmetric(gadge_elem, lower);

    // external product of lower and neg_secret_key
    data_gsw.external_product(neg_secret_key, lower, coeff_count, rgsw[i]);
    rgsw[i + l] = lower;
  }


  return rgsw;
}





