The goal of this file is to help understand the implementation of `GSWCiphertext`. Let's start with my understanding of RGSW scheme. 



### From GSW to RGSW

> My understanding.

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



==TODO==

#### Gadget Decomposition of TLWE sample:

Let $v$ be a TLWE sample. The decomposition of $v$ outputs an element on a polynomial ring: $u = \operatorname{Dec}(v) \in \mathcal{R}$. Then a correct decomposition means $\| u \cdot G - v\|_\infty < \varepsilon $. 

==TODO==

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240809024614114.png " style="width:50%;" />
    <figcaption>  </figcaption>
  </figure>
</center>



#### RGSW gadget

$$
\begin{align*}
g^{(\ell  \times 1)} &= \left(B^{\log q / \log B-1}, B^{\log q / \log B-2}, \cdots, B^{\log q / \log B- \ell }\right)\\
&= (B^{l-1}, \ldots, B^0)
\end{align*}
$$







#### Example and Difference: 

In TGSW, all coefficients are between 0 and 1, where in RGSW, coefficients are in $\mathbb{Z}_q$, where $q$ can be very large (e.g. 72 bits).

- TGSW: $B = 10, \ell = 3, g = (1/10, 1/10^2, 0.001)$. 
- RGSW: $B = 10, \ell = 3, g = (1/10^2, 1/10^1, 1/10^0)$. 























Enc in TGSW: 

plaintext Message: 423

ciphertext = Z + mu * G = 42.3, 4.23, 0.423



Enc in RGSW

plaintext Message: 837

83700, 8370, 837











#### Quick Result

In RGSW, $B^k$ uses ciphertext modulus $q$. In this way, the gadget decomposition is guaranteed to be correct.







### Design of GSWCiphertext

#### The problem:

The goal is to use the GSWCiphertext, which has the form $C = Z + \mu \cdot G$. If we write it out, it looks like: 
$$
\begin{bmatrix}
a_1 + \mu \cdot g_1 & b_1 \\
\vdots & \vdots\\
a_l + \mu \cdot g_l & b_l\\
a_{l+1} &  b_{l+1} + \mu \cdot g_1\\
\vdots & \vdots\\
a_{2l} &  b_{2l} + \mu \cdot g_l\\
\end{bmatrix}
=
\begin{bmatrix}
a_1 + \mu \cdot g_1 & a_1 \cdot s + e_1 \\
\vdots & \vdots\\
a_l + \mu \cdot g_l & a_l \cdot s + e_l\\
a_{l+1} &  (a_{l+1} \cdot s + e_{l+1}) + \mu \cdot g_1\\
\vdots & \vdots\\
a_{2l} &  (a_{2l} \cdot s + e_{2l}) + \mu \cdot g_l\\
\end{bmatrix}
$$
Where $\mu$ is the message, $s$ is the client secret key.



In Onion-Ring ORAM, they interpret this ciphertext as: 

<center>
  <figure>
    <img src=" https://raw.githubusercontent.com/helloboyxxx/images-for-notes/master/uPic/image-20240809040225749.png " style="width:50%;" />
    <figcaption>  </figcaption>
  </figure>
</center>

The problem is that the representation $\operatorname{RLWE}(\mu \cdot g_k)$ is invalid: what if $\mu \cdot g_k > $ plaintext modulus? 

RLWE($\mu \cdot B^k$). 

- We cannot put this multiplication result as a plaintext then encrypt. 

- If we wrap this result in plaintext modulus, i.e. we encrypt $\operatorname{RLWE}(\operatorname{wrap}(\mu \cdot g_k))$, how do we decrypt and reconstruct this result? 
- Most importantly, the goal is to QueryUnpack to $\operatorname{RGSW}(\mu)$, specifically, $\operatorname{RGSW}(0)$ or $\operatorname{RGSW}(1)$, wrapping will not help unpack to correct value. 



#### Weird but working GSWCiphertext:

In short: RGSW can be represented and stored in BFV form, but cannot be interpreted / encrypted / decrypted using BFV.

To create a RGSW ciphertext, the trick is to "encrypt-then-add", strickly following the RGSW definition. The following is a high-level of `GSWEval::encrypt_plain_to_gsw`. 

- Create $2 \ell$ rows of zero BFV (corresponds to $Z$).
- 









- then add the gadget value if we want $\operatorname{RGSW}(1)$ (corresponds to $\mu \cdot G$). This trick works when $\mu$ is a constant polynomial, i.e., $\mu = 0$ or $\mu = 1$.













Imagine this bijection: $g_k \mapsto \mu_k$. Every gadget value corresponds to a special plaintext polynomial $\mu_k$ such that $\operatorname{BFV}(\mu_k) = \text{the } (\ell +k) \text{ 'th row of }\operatorname{RGSW}(1)$. Then, 



















