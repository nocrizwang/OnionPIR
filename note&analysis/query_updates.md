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
It is not because the values are not filled in, but is because the first $2/3$ values are all rounded to 0. This is of course weird, but it works now.



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

Better unit test.









