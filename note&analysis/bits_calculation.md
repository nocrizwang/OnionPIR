The goal here is to understand that is the `bits` and why is the `base_log2_` calculated this way. Note that this is a guess made by Yue. 

In the explanation for `SEALContext` class in `SEAL/native/src/seal/context.h`, it has: "By default, `SEALContext` creates a chain of `SEALContext::ContextData` instances. The first one in the chain corresponds to special encryption parameters that are reserved to be used by the various key classes (SecretKey, PublicKey, etc.)." Since we need a find a place for storing RGSW encryption, my interpretation for the "first one in the chain" must be able to have enough bits to represent any RGSW gadget ciphertext, meaning that we should be able to express a RGSW gadget vector. Each element is a RLWE element, so we need to have enough bits for expressing these RLWE elements. The modulus must be large enough. From the Onion Ring ORAM paper(https://eprint.iacr.org/2019/736), it breifly defines the RGSW gadget vector. Notice that we should express $B^l$. 

Now, in the code, the number of bits we can use for storing a default BFV coefficient is `bits`.  Specifically, `bits = 72` when poly_modulus_degree is set to 4096. As for `base_log2_`, check the calculation below. 
$$
\begin{align*}
B^l \leq 2^\mathbf{bits}\\
\log_2 B^l \leq \mathbf{bits}\\
l \cdot \log_2B \leq \mathbf{bits}\\
\log_2B \leq \frac{\mathbf{bits}}{l}
\end{align*}
$$













