### `QueryPack`

There are two types of encryption used in our queries. The first dimension uses BFV, the rests are RGSW. The goal of QueryPack algo is to **write all parameters as coefficients of a single BFV encryption**. Since we have many dimensions, the number of queries is in $O(\log N)$, where $N$ is the size of the database, the number of coefficients in a single BFV ciphertext is enough for packing a reasonable number of indices for each dimension. 

In the pseudocode, each $b_{i, j}$ is consists of $f$ many "values". For the first dimension, only two values $(c_0, c_1)$ are needed for a single BFV ciphertext. For the rest queries, each entry is a RGSW ciphertext consists of $l$ many important parameters, which are the first $l$ rows of RGSW ciphertext. 

The **question** here is: each "parameter" here is a plaintext polynomial in $R \mod t$. How can we encode this many polynomials in a single BFV ciphertext? A single BFV ciphertext is made up of two polynomials in $R \mod t$. 

Quote from OnionPIR: "In our implementation, each ciphertext has 𝑛 = 4096 plaintext slots, so we pack all these
plaintexts into a single BFV ciphertext". What is the meaning of this? 



### `QueryUnpack`

The goal is to generate the normal BFV and RGSW queries from the single BFV ciphertext created in `QueryPack`. 

`expandRlwe` expands the single BFV ciphertext to many BFV ciphertexts. Since the first $2N_1$ ciphertexts are already in BFV, no need to do any transformation. For the rest dimensions, we need to reconstruct the RGSW queries from these BFV. 

- For each dimension
  - For each query entry
    - Reconstruct row $k$ and $k + l$ in RGSW ciphertext using expanded BFV ciphertext.



**Question:** How does this RGSW ciphertext looks like? Specifically, what is the meaning of $\mathbf{Z}$ in the ciphertext?

RGSW ciphertext:
$$
g^{(l \times 1)} = (B^{\log q / \log B - 1}, B^{\log q / \log B - 2}, \ldots, B^{\log q / \log B - l})\\
\mathbf{G}=\mathbf{I}_2 \vee g=\left[\begin{array}{ll}
g & 0 \\
0 & g
\end{array}\right] \in R^{(2 l \times 2)}\\
\mathbf{C} = \mathbf{Z} + m \cdot \mathbf{G}
$$




### Questions: 

If we increase the size of the ciphertext, we leave more room for noise. But that has an increase of $F = \frac{2 \log q}{ \log t}$, the ciphertext expansion factor. 















