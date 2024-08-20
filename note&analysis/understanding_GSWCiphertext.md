The goal of this file is to help understand the GSW scheme and the implementation of `GSWCiphertext`in OnionPIR code. Let's start with my understanding of GSW scheme. 

### From TGSW to RGSW

RGSW is a ring variation of [GSW scheme](https://eprint.iacr.org/2013/340). I do not see any formal paper defining this scheme. But, I do find this particular paper helpful: [Faster Fully Homomorphic Encryption: Bootstrapping in less than 0.1 Seconds](https://eprint.iacr.org/2016/870). Conceptually, TFHE works on torus polynomial: $\mathbb{T}_N[X] = \mathbb{R}[X] / (X^N + 1) \mod 1$, where RGSW works on polynomial ring: $R[X] = \mathbb{Z}[X] / (X^N + 1)$. $N$ is the degree of the polynomial in both cases. The second definition is briefly given by: [Onion Ring ORAM: Efficient Constant Bandwidth Oblivious RAM from (Leveled) TFHE](https://eprint.iacr.org/2019/736). 

Let's first discuss GSW scheme (TGSW, the torus version) and briefly touch on external product (the use of GSW gadget). Then, I will present how we apply it in RGSW scheme.

Given a base $B$ and a length parameter $\ell$, we define a gadget vector:
$$
g^{(\ell \times 1)} = (1/B, \ldots, 1/B^\ell)^T
$$

> Example: $B = 10, \ell = 3, g = (0.1, 0.01, 0.001)$

Then the gadget. This is a simple 
$$
G=\mathbf{I}_2 \otimes g=\left[\begin{array}{ll}
g & 0 \\
0 & g
\end{array}\right] \in \mathbb{T}_N[X]^{2 \ell \times 2}
$$




$$
\text{TGSW ciphertext: }C = Z + \mu \cdot G
$$

Where $Z$ is $2\ell$ rows of $\operatorname{TLWE}(0)$.

#### RGSW gadget

$$
\begin{align*}
g^{(\ell  \times 1)} &= \left(B^{\log q / \log B-1}, B^{\log q / \log B-2}, \cdots, B^{\log q / \log B- \ell }\right)\\
&= (B^{l-1}, \ldots, B^0)
\end{align*}
$$

Where $q$ is the coefficient modulus for ciphertext. 



#### The connection

In application, we deal with TGSW and RGSW in the same way, but only in different range. Since we cannot express $\mathbb{R}$ in infinite precision – we are in discrete case – TGSW is actually implemented as RGSW. RGSW has integer values from 1 to $q$ and 1 to $t$, where TGSW has discret values from 0 to 1. They share all the algorithms while only the range of number expression differs.

#### Gadget Decomposition LWE samples:

Let $\pmb{v}$ be a TLWE sample. The decomposition of $v$ outputs an element on a polynomial ring: $\pmb{u} = \operatorname{Decomp}(\pmb{v}) \in \mathcal{R}$. Then a correct decomposition means $\| \pmb{u} \cdot G - \pmb{v}\|_\infty < \varepsilon $. We can think of decomposition as a way we extract bits from huge numbers. 

Example:

- TGSW: $B = 10, \ell = 3, g = (1/10, 1/10^2, 1 / 10^3)$, then decomposing $v = 0.468$ becomes: $\operatorname{Decomp}(v) = (4, 6, 8)$.
- RGSW: $B = 10, \ell = 3, g = (10^2, 10^1, 10^0)$, then decomposing $v = 839$ becomes: $\operatorname{Decomp}(v) = (8, 3, 9)$.

#### External Product and the Usage of Gadgets

Check theorem 3.14 in https://eprint.iacr.org/2016/870 to for the details of external product. In the proof, at some point, the decomposed RLWE is multiplied by the gadget in the GSW ciphertext. We see a cancelation during this multiplication, which makes the homomorphic multiplication possible under the hood.

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/Screenshot 2024-08-17 at 3.15.43 PM.png " style="width:70%;" />
    <figcaption>  </figcaption>
  </figure>
</center>





### Interpretation v.s. Storage

> There are a few points easy to mess up. Since RGSW and TGSW are actually the same thing, I will use RGSW here.

The first thing to notice is is that we should not interpret each row of RGSW as RLWE (BFV), even though we can (and will) represent them in RLWE form. The $Z$ matrix are rows of RLWE(0). If we treat RLWE as black box, then adding extra values to the coefficients of RLWE will make the ciphertext unpredictable. In fact, we can encrypt a message to GSW ciphertext, but cannot decrypt them. In our case, BFV scheme scales the message by a factor (delta) during the encryption state. Check [Introduction to the BFV encryption scheme](https://inferati.com/blog/fhe-schemes-bfv) for an introduction to BFV scheme. 

In our case, since we can store each row or RGSW as RLWE, we can use a very specific trick to pack the query, and use the algorithm 3 in Onion-Ring ORAM as a subroutine to unpack the query. By doing this, we reduce the online communication. The following is an important observation. I will use the notation in the link above.

In BFV scheme, we have: 
$$
\operatorname{BFV}(0) =
\begin{cases}
C_1 = [-(a \cdot SK + e)\cdot u + e_1]_q = [-a \cdot SK \cdot u - e\cdot u + e_1]_q\\
C_2 = [a \cdot u + e_2]_q
\end{cases}
$$
Therefore, if we only look at the first $l$ rows of a RGSW ciphertext, the $i^{\text{th}}$ row looks like: 
$$
\begin{align*}
\operatorname{RGSW}(M)_i &= Z_i + M \cdot G_i = 
\left(\;
C_{i, 1} + M g_i, \;
C_{i, 2}
\;\right)\\
&=
\left(\;
-(a \cdot SK + e)\cdot u + e_1 + M g_i, \;
C_{i, 2}
\;\right)\\
&= \operatorname{BFV^*}(M g_i/\Delta)

\end{align*}
$$

Here, I am using $\operatorname{BFV^*}( M g_i / \Delta)$  for a simpler expression. It is not a real BFV ciphertext as we won't get the exact RGSW ciphertext if we encrypt $M g_i / \Delta$ when $\Delta > Mg_i$. In a discrete case, this division gives 0.

Next, the bottom $l$ rows. Let $j \in [l]$ but represent the index of the second $l$ rows. So, $Z_j$ actually means $Z_{j + l}$.
$$
\begin{align*}
\operatorname{RGSW}(M)_j 
&= Z_j + M \cdot G =
\left(\;
C_{j, 1}, \;
C_{j, 2} + Mg_j
\;\right)\\
&=
\left(\;
-(a \cdot SK + e)\cdot u + e_1, \;
a \cdot u + e_2 + Mg_i
\;\right)\\

\end{align*}
$$
If we treat the second term as a new $C_{j, 2}'$, decrypting this row using BFV decryption gives us: 
$$
\begin{align*}
\text{message}(\operatorname{RGSW}(M)_j) &= 
\left[\lfloor \left( 
C_{j, 1} + (C_{j, 2} + Mg_j) \cdot \mathrm{SK} 
\right)
/ \Delta \rceil\right]_t\\
&= \left[\lfloor 
\left(\left(
-a \cdot u \cdot \mathrm{SK} - e \cdot u + e_1 \right) 
+ (a \cdot u \cdot \mathrm{SK} + e_2 \cdot \mathrm{SK} + Mg_i \cdot \mathrm{SK})
\right)
/ \Delta 
\rceil\right]_t\\
&\approx (Mg_j/ \Delta) \cdot \mathrm{SK}\\
&\Updownarrow\\
\operatorname{RGSW}(M)_j &= \operatorname{BFV^*}((Mg_j/ \Delta) \cdot \mathrm{SK})

\end{align*}
$$



Then the trick is to perform external product betweeen $\operatorname{RGSW}(\mathrm{SK})$ and the first $l$ rows, $\operatorname{BFV^*}(Mg_i/\Delta)$, to recreate the second $l$ rows of the query RGSW ciphertexts.
$$
\operatorname{RGSW}(\mathrm{SK}) \boxdot \operatorname{BFV^*}(Mg_i/\Delta) = \operatorname{BFV^*}((Mg_i/\Delta) \cdot SK)
$$











#### Example Gadget and Difference: 

In TGSW, all coefficients are between 0 and 1, where in RGSW, coefficients are in $\mathbb{Z}_q$, where $q$ can be very large (e.g. 72 bits).

- TGSW: $B = 10, \ell = 3, g = (1/10, 1/10^2, 0.001)$. 
- RGSW: $B = 10, \ell = 3, g = (1/10^2, 1/10^1, 1/10^0)$. 



















