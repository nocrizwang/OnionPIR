# Updates on query related functionalities and details

The code was different from the pseudocode in OnionPIR paper. Yue made some changes on the code so to align with the pseudocode logic.



### Updates on `generate_query` on client side.

- Previously, if the `query_indexes[i] == 0`for dimension $i$, the code packed some "special values" to the coefficients of the query. Correspondingly, in `evaluate_gsw_product` on the server side, if the selection vector is RGSW(0), then it outputs the second half of the given vector. These old code are not consistent with the output of `get_query_indexes`, and are againsts the conventional vector order. Hence, the first update is to change the code so that we indeed pack the value 1 when `query_indexes[i] == 1`.
- Previously, the `coef`, which corresponds to the RGSW gadget value, are in reversed order. That is, for gadget = $(1/B, \ldots, 1/B^l)$, the previous code insert in the reversed order `coef` $=[B^{l-1}, B^{l-2}, \ldots, B^0]$. Corresponding changes are in: `external_prod.cpp > GSWEval::decomp_rlwe` and `external_prod.cpp > GSWEval::encrypt_plain_to_gsw`. The changed code aligns with algorithm 1 in [Faster Fully Homomorphic Encryption: Bootstrapping in less than 0.1 Seconds](https://eprint.iacr.org/2016/870).
- TODO: also encrypt the first $l$ rows for RGSW queries. Worth it? The current `query_to_gsw` takes about 60ms for each dimension. 





### Question on exsisting `generate_query` code:

Only $1 / 3$ of the RGSW gadget are used, others are 0. In the following example, $B = 256 = \text{0x100}$. 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240723222155623.png " style="width:50%;" />
    <figcaption> Decrypted RGSW(1) in "problematic" generate_query </figcaption>
  </figure>
</center>

This could be serious because $l$ and $B$ controls the gadget, which affects the ability to decompose and reconstruct values. In the current algorithm,  only with $l \geq 8$ can we guarantee sufficient precision to retrieve the correct data (check the final section for other default values.) 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240723235037356.png" alt="image-20240723235037356 " style="width:40%;" />
    <figcaption> Retrieved result v.s. Actual data </figcaption>
  </figure>
</center>



### The most reasonable fix: 

The following version has the exact same structure as pseudocode:

```cpp
PirQuery PirClient::generate_query(std::uint64_t entry_index) {

  // Get the corresponding index of the plaintext in the database
  size_t plaintext_index = get_database_plain_index(entry_index);
  std::vector<size_t> query_indexes = get_query_indexes(plaintext_index);
  PRINT_INT_ARRAY("query_indexes", query_indexes.data(), query_indexes.size());
  uint64_t coeff_count = params_.poly_modulus_degree(); // 4096

  // The number of bits required for the first dimension is equal to the size of the first dimension
  uint64_t msg_size = dims_[0] + pir_params_.get_l() * (dims_.size() - 1);
  uint64_t bits_per_ciphertext = 1; // padding msg_size to the next power of 2

  while (bits_per_ciphertext < msg_size)
    bits_per_ciphertext *= 2;

  seal::Plaintext plain_query(coeff_count); // we allow 4096 coefficients in the plaintext polynomial to be set as suggested in the paper.

  // Algorithm 1 from the OnionPIR Paper
  // We set the corresponding coefficient to the inverse so the value of the
  // expanded ciphertext will be 1
  uint64_t inverse = 0;
  uint64_t plain_modulus = params_.plain_modulus().value(); // example: 16777259
  seal::util::try_invert_uint_mod(bits_per_ciphertext, plain_modulus, inverse);

  // Add the first dimension query vector to the query
  plain_query[ query_indexes[0] ] = inverse;
  
  // ======= Now we handle the remaining dimensions =======

  DEBUG_PRINT("inverse: " << inverse);
  DEBUG_PRINT("plain_modulus: " << plain_modulus << "\n");

  auto l = pir_params_.get_l();
  auto base_log2 = pir_params_.get_base_log2();

  uint64_t gadget[l + 1];  // RGSW gadget
  uint64_t curr_exp = 1;
  for (int i = 0; i < l + 1; i++) {
    // exponents[i] = curr_exp;
    // we inverse the exponents to get the correct RGSW gadget
    seal::util::try_invert_uint_mod(curr_exp, plain_modulus, gadget[i]);
    DEBUG_PRINT("gadget[" << i << "]: " << gadget[i]);
    curr_exp = (curr_exp << base_log2) % plain_modulus; // multiply by B and take mod every time
  }

  // This for-loop corresponds to the for-loop in Algorithm 1 from the OnionPIR paper
  int ptr = dims_[0];
  for (int i = 1; i < query_indexes.size(); i++) {  // dimensions
    // we use this if statement to replce the j for loop in Algorithm 1. This is because N_i = 2 for all i > 0
    // When 0 is requested, we use initial encrypted value of PirQuery query, where the coefficients decrypts to 0. 
    // When 1 is requested, we add special values to the coefficients of the query so that they decrypts to correct GSW(1) values.
    if (query_indexes[i] == 1) {
      for (int k = 1; k < l + 1; k++) {
        // under this moduli, the coeff is (B^{-1}, B^{-2}, ..., B^{-l}) / bits_per_ciphertext
        plain_query[ptr] = (gadget[k] * inverse) % plain_modulus;
        DEBUG_PRINT("plain_query[" << ptr << "]: " << plain_query[ptr]);
        ptr++;
      }
      DEBUG_PRINT(" ");
    }
    // Otherwise we use the default value 0.
  }

  // ======= Last line of the pseudocode =======
  PirQuery query; // pt in paper
  encryptor_->encrypt_symmetric(plain_query, query);  // $\tilde c$ in paper
  return query;
}
```

#### Some evidence showing that we SHOULD use this design: 

All output below uses the "default" pir param. Check the final section.

Let's first examine this examine output of this packing algorithm. 

```pseudocode
inverse: 12484640
plain_modulus: 16777259

// The following is the correct gadget, where gadget[k] = 1/(B^k)
gadget[0]: 1
gadget[1]: 8192021
gadget[2]: 4291851
gadget[3]: 6242701
gadget[4]: 14245734
gadget[5]: 13556098
gadget[6]: 8048366
gadget[7]: 3570392
gadget[8]: 7878287
gadget[9]: 13858906

// The followings are:   gadget[k] * inverse % plain_modulus
plain_query[256]: 10534555
plain_query[257]: 11509980
plain_query[258]: 7122867
plain_query[259]: 6778049
plain_query[260]: 4024183
plain_query[261]: 1785196
plain_query[262]: 12327773
plain_query[263]: 6929453
plain_query[264]: 16345574

Dimension 1: 0x7D0015 0x417D0B 0x5F418D 0xD95F66 0xCED982 0x7ACEEE 0x367AD8 0x78368F 0xD3785A 
```

To verify gadget: try to see if $\text{gadget}[k] \cdot B^{k} \equiv  1 \mod \text{plain\_modulus}$.
Example: take gadget[3]:  $16777259 \mid ((6242701 \cdot  256^3) - 1)$ does hold.



The final line is a single Decrypted RGSW ciphertext. Specifically, Dec(RGSW(1)). This corresponds to the gadget perfectly.



**The ==down side== of this fix is that we have to change the external product as well. My current guess is that the external product also has some buggy code.**









---

### Default PIR param

```cpp
#define DB_SZ       1 << 15
#define NUM_DIM     8
#define NUM_ENTRIES 1 << 15
#define ENTRY_SZ    12000
#define GSW_L       9
#define GSW_L_KEY   9
```

#### Some expected values:

```
==============================================================
                       PIR PARAMETERS                         
==============================================================
num_entries_											 = 32768
l_																= 9
base_log2_												  = 8
entry_size_												   = 12000
DBSize_ (num plaintexts in database)        = 32768
DBCapacity (max num of entries)      		   = 32768
dimensions_                           						 = [ 256 2 2 2 2 2 2 2 ]
seal_params_.poly_modulus_degree()        = 4096
seal_params_.coeff_modulus().bit_count   = [36 + 36 + 37] bits
seal_params_.coeff_modulus().size()      	  = 3
seal_params_.plain_modulus().bitcount() = 25
==============================================================


plain_modulus = 16777259
inverse of 256 in plain_modulus: 12484640
context_data->parms().coeff_modulus() = {68585185425, 68585013729}

```



---

### TODO: 

Better profiling method.







