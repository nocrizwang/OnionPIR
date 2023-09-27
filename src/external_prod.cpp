#include "external_prod.h"
#include "seal/util/polyarithsmallmod.h"
#include "utils.h"
#include <cassert>

void external_product(GSWCiphertext &gsw_enc, seal::Ciphertext bfv,
                      std::shared_ptr<seal::SEALContext> context, int l,
                      size_t ct_poly_size, seal::Ciphertext &res_ct) {

  const auto &context_data = context->get_context_data(bfv.parms_id());
  auto &parms2 = context_data->parms();
  auto &coeff_modulus = parms2.coeff_modulus();
  size_t coeff_count = parms2.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();

  auto ntt_tables = context_data->small_ntt_tables();

  std::vector<std::vector<uint64_t>> decomposed_bfv;

  decomp_rlwe(bfv, l, context, decomposed_bfv, 2);
  // Here we compute a cross product between the transpose of the decomposed BFV
  // (a 2l vector of polynomials) and the GSW ciphertext (a 2lx2 matrix of
  // polynomials) to obtain a size-2 vector of polynomials, which is exactly our
  // result ciphertext. We use an NTT multiplication to speed up polynomial
  // multiplication, assuming that both the GSWCiphertext and decomposed bfv is
  // in polynomial coefficient representation.

  for (auto &poly : gsw_enc) {
    seal::util::CoeffIter gsw_poly_ptr(poly);
    seal::util::ntt_negacyclic_harvey(gsw_poly_ptr, *ntt_tables);
  }
  for (auto &poly : decomposed_bfv) {
    seal::util::CoeffIter bfv_poly_ptr(poly);
    seal::util::ntt_negacyclic_harvey(bfv_poly_ptr, *ntt_tables);
  }

  // Use the delayed mod speedup
  std::vector<std::vector<uint128_t>> result(
      2, std::vector<uint128_t>(coeff_count * coeff_mod_count, 0));
  for (int k = 0; k < 2; ++k) {
    for (size_t j = 0; j < 2 * l; j++) {
      seal::util::ConstCoeffIter encrypted_gsw_ptr(gsw_enc[k * 2 * l + j]);
      seal::util::ConstCoeffIter encrypted_rlwe_ptr(decomposed_bfv[j]);
      utils::multiply_poly_acum(encrypted_rlwe_ptr, encrypted_gsw_ptr,
                                coeff_count * coeff_mod_count,
                                result[k].data());
    }
  }

  for (size_t poly_id = 0; poly_id < 2; poly_id++) {
    auto ct_ptr = res_ct.data(poly_id);
    auto pt_ptr = result[poly_id];

    for (int mod_id = 0; mod_id < coeff_mod_count; mod_id++) {
      auto mod_idx = (mod_id * coeff_count);
      auto mod = static_cast<uint64_t>(coeff_modulus[mod_id].value());
      for (int coeff_id = 0; coeff_id < coeff_count; coeff_id++) {
        ct_ptr[coeff_id + mod_idx] =
            static_cast<uint64_t>(pt_ptr[coeff_id + mod_idx] % mod);
      }
    }
  }
}

void decomp_rlwe(seal::Ciphertext ct, const uint64_t l,
                 std::shared_ptr<seal::SEALContext> context,
                 std::vector<std::vector<uint64_t>> output,
                 const uint64_t base_log2) {

  assert(output.size() == 0);
  output.reserve(2 * l);

  // Get parameters
  const uint64_t base = UINT64_C(1) << base_log2;
  const uint64_t mask = base - 1;

  const auto &context_data = context->get_context_data(ct.parms_id());
  auto &parms = context_data->parms();
  auto &coeff_modulus = parms.coeff_modulus();
  size_t coeff_count = parms.poly_modulus_degree();
  size_t coeff_mod_count = coeff_modulus.size();
  size_t ct_poly_count = ct.size();
  assert(ct_poly_count == 2);

  seal::util::RNSBase *rns_base = context_data->rns_tool()->base_q();
  auto pool = seal::MemoryManager::GetPool();

  for (auto mod : coeff_modulus) {
    if ((mod.value() >> (l * base_log2)) != 0) {
      throw std::invalid_argument(
          "L * base_log2 does not cover the coefficient modulus");
    }
  }

  // Start decomposing row wise. Note that the modulus of each row is
  // base^(l-row)

  std::vector<uint64_t> data(coeff_count * coeff_mod_count);
  for (int j = 0; j < ct_poly_count; j++) {
    uint64_t *poly_ptr = ct.data(j);

    memcpy(data.data(), poly_ptr,
           coeff_count * coeff_mod_count * sizeof(uint64_t));
    rns_base->compose_array(data.data(), coeff_count, pool);

    for (int p = l - 1; p >= 0; p--) {
      std::vector<uint64_t> row = data;
      const int shift_amount = p * base_log2;

      for (size_t k = 0; k < coeff_count; k++) {
        auto ptr = row.data() + k * coeff_mod_count;
        seal::util::right_shift_uint(ptr, shift_amount, coeff_mod_count, ptr);
        ptr[0] &= mask;
        for (int i = 1; i < coeff_mod_count; i++) {
          ptr[i] = 0;
        }
      }

      rns_base->decompose_array(row.data(), coeff_count, pool);

      output[j] = std::move(row);
    }
  }
}

void query_to_gsw(std::vector<seal::Ciphertext> query, const uint64_t l,
                  std::shared_ptr<seal::SEALContext::ContextData> context_data,
                  GSWCiphertext &output, const uint64_t base_log2) {
  assert(query.size() == l);
  for (int i = 0; i < l; i++) {
    // query[i]
  }
}
