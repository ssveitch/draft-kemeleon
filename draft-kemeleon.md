---
title: "Kemeleon Encodings"
abbrev: "Kemeleon"
category: info

docname: draft-kemeleon-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword: Internet-Draft
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "ssveitch/draft-kemeleon"
  latest: "https://ssveitch.github.io/draft-kemeleon/draft-kemeleon.html"

author:
 -
    fullname: Felix Günther
    organization: IBM Research Europe - Zurich
    email: mail@felixguenther.info

 -
    fullname: Douglas Stebila
    organization: University of Waterloo
    email: dstebila@uwaterloo.ca

 -
    fullname: Shannon Veitch
    organization: ETH Zurich
    email: shannon.veitch@inf.ethz.ch

normative:

  FIPS203: DOI.10.6028/NIST.FIPS.203
  RFC9380:

  ELL2:
    title: "Elligator Squared: Uniform Points on Elliptic Curves of Prime Order as Uniform Random Strings"
    target: https://eprint.iacr.org/2014/043
    date: 2014
    author:
      -
        ins: M. Tibouchi
        name:  Mehdi Tibouchi

  GSV24:
    title: Obfuscated Key Exchange
    target: https://eprint.iacr.org/2024/1086
    date: 2024
    author:
      -
        ins: F. Günther
        name: Felix Günther
      -
        ins: D. Stebila
        name: Douglas Stebila
      -
        ins: S. Veitch
        name: Shannon Veitch

informative:

   OBFS4:
    title: obfs4 (The obfourscator)
    target: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/blob/HEAD/doc/obfs4-spec.txt

--- abstract

This document specifies Kemeleon encoding, algorithms for encoding ML-KEM public keys and ciphertexts as random bytestrings.
Kemeleon encodings provide obfuscation of public keys and ciphertexts, relying on module LWE assumptions.
This document specifies a number of variants of these encodings, with differing failure rates, output sizes, and performance profiles.

--- middle

# Introduction

ML-KEM {{FIPS203}} is a post-quantum key-encapsulation mechanism (KEM) recently standardized by NIST,
Many applications are transitioning from classical Diffie-Hellman (DH) based solutions to constructions based on ML-KEM.
The use of Elligator and related Hash-to-Curve {{RFC9380}} algorithms are ubiquitous in DH-based protocols where DH shares are required to be encoded as, and look indistinguishable from, random bytestrings.
For example, applications using Elligator include protocols used for censorship circumvention in Tor {{OBFS4}}, password-authenticated key exchange (PAKE) protocols {{?CPACE=I-D.irtf-cfrg-cpace}} {{?OPAQUE=I-D.irtf-cfrg-opaque}}, and private set intersection (PSI) {{?ECDH-PSI=I-D.ecdh-psi}}.

For the post-quantum transition, an analogous encoding for (ML-)KEM public keys and ciphertexts to random bytestrings is required.
This document specifies such an encoding, Kemeleon, for ML-KEM public keys and ciphertexts.
Kemeleon was introduced in {{GSV24}} for building an (post-quantum) "obfuscated" KEM whose public keys and ciphertexts are indistinguishable from random.
Beyond the original construction, this document additionally specifies variants that avoid the encoding failing or the use of large integer computations, or allow for a deterministic encoding.
Aside from these variants, it is notable that the Kemeleon encodings of public keys results in smaller representations than in the original ML-KEM specification.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Notation / ML-KEM Background

A KEM consists of three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm that, with no input, generates a public key `pk` and a secret key `sk`.
- `Encaps(pk) -> (c, K)`: A probabilistic encapsulation algorithm that takes as input a public key `pk`, and outputs a ciphertext `ct` and shared secret key `K`.
- `Decaps(sk, c) -> K`: A decapsulation algorithm that takes as input a secret key `sk` and ciphertext `c`, and outputs a shared secret key `K`.

The following variables and functions are adopted from {{FIPS203}}:

- `q = 3329`, `n = 256`
- `Compress_d : x -> round((2d/q)*x) mod 2d` (Equation 4.7)
- `Decompress_d : y -> round((q/2d)*y)` (Equation 4.8)
- remaining parameters `k`, `d_u`, `d_v`, etc. are defined by the respective ML-KEM parameter set

`ML-KEM.KeyGen()` (Section 7.1 {{FIPS203}}) produces a public key, `pk`, (termed an encapsulation key in {{FIPS203}}) and a private key, `sk`, (decapsulation key).
Public keys consist of byte-encoded vectors of coefficients in Z_q, where each coefficient is encoded in 12 bits, together with a 32-byte seed for generating the matrix `A`.
`ML-KEM.Encaps(pk)` (Section 7.2 {{FIPS203}}) produces ciphertexts consisting of byte-encoded compressed vectors of cofficients, where each coefficient in Z_q is compressed by a certain number of bits (depending on the ML-KEM parameter set).

The following terms and notation are used throughout this document:

- `msb(x)` refers to the most significant bit of the value x
- `a[i]` denotes the `i`th position of a vector `a` of coefficients
- `concat(x0, ..., xN)`: returns the concatenation of bytestrings.

# Kemeleon Encoding

At a high level, the constructions in this document instantiate the following functions:

- `EncodePk(pk) -> epk` is the (possibly randomized) encoding algorithm that on input a public key, outputs an obfuscated public key or an error.
- `DecodePk(epk) -> pk` is the deterministic decoding algorithm that on input an obfuscated public key, outputs a public key.
- `EncodeCtxt(c) -> ec` is the (possibly randomized) encoding algorithm that on input a ciphertext, outputs an obfuscated ciphertext or an error.
- `DecodeCtxt(ec) -> c` is the deterministic decoding algorithm that on input an obfuscated ciphertext, outputs a ciphertext.

## Common Functions

~~~
VectorEncode(a):
   r = 0
   for i from 1 to k*n:
      r += q^(i-1)*a[i]
   if msb(r) == 1:
      return err
   else:
      return r
~~~

~~~
VectorDecode(r):
   for i from 1 to k*n:
      a[i] = r % q
      r = r // q
   return a
~~~

The following algorithm samples an uncompressed pre-image of a coefficient c at random.
The mapping is based on the `Compress_d`, `Decompress_d` algorithms from (Section 4.2.1 {{FIPS203}}).

TODO:
~~~
RecoverFrom_d(u,c):
   if d == 10:
      if Compress_d(u - 2) == c:
         rand <--$ [-2,-1,0,1]
      else:
         rand <--$ [-1,0,1]
      return u + rand
   if d == 11:

   else:
      return err
~~~

## Encoding Public Keys

~~~
Kemeleon.EncodePk(pk = (t, rho)):
   r = VectorEncode(t)
   if r == err:
      return err
   else:
      return concat(r,rho)
~~~

~~~
Kemeleon.DecodePk(epk):
   r,rho = epk // rho is fixed length
   t = VectorDecode(r)
   return (t, rho)
~~~

## Encoding Ciphertexts

The following algorithms use global parameters `d_u`, `d_v` defined by the respective ML-KEM parameter set.

~~~
Kemeleon.EncodeCtxt(c = (c_1,c_2)):
   d = d_u
   u = Decompress_d(c_1,d)
   for i from 1 to k*n:
      u[i] = RecoverFrom_d(u[i],c_1[i])
   r = VectorEncode(u)
   if r == err:
      return err
   for i from 1 to n:
      if c_2[1] == 0:
         return err with prob. 1/ceil(q/(2^d_v))
   return concat(r,c_2)
~~~

~~~
Kemeleon.DecodeCtxt(ec):
   r,c_2 = ec // c_2 is fixed length
   u = VectorDecode(r)
   c_1 = Compress_q(u,d_u)
   return (c_1,c_2)
~~~

## Non-Rejection Sampling Variant

Applying a technique from {{ELL2}} (Section 3.4), the original `Kemeleon` construction can be adapted to avoid rejection sampling.
This results in slightly larger output sizes, but the encoding algorithm never fails.
For this variant, where `r` is the encoded vector before rejection occurs in `VectorEncode`, we then choose `m` at random from `[floor((2^(b+t)-r)/(q^(k*n)))]`, where `b = log_2(q^(k*n))` and `t = 128`, and return `r + m*q^(k*n)`.
One MAY select `t` to be a desired security parameter.
This variant results in encoded values whose statistical distance from uniform is at most `2^t`.
For all inputs (public keys or ciphertexts), this results in an increased output size of `t` bits, where `t` is the security parameter.
For example, with `t=128`, this increases the output size by 16 bytes.

## Faster Arithmetic Variant

Observing that `q = 3329 = 13*2^8+1`, a variant of `Kemeleon` with faster integer arithmetic can be specified.
First, the encoding rejects any polynomial with a coefficient equal to `q-1 = 3328`.
This ensures that all arithmetic can be computed with values modulo `q-1 = 13*2^8`.
Then, note that rather than accumulating values to a large integer mod `q^(k*n)`, it is only required to accumulate values to an integer mod `13^(k*n)`, while keeping track of the 8 lower order bits of each coefficient.
The output size of the encoding does not change, but this results in an increased rejection rate.

In particular, {{fast-succ-prob}} gives success probabilities for public key and ciphertext encodings:

| Parameter     | Pk success probability | Ctxt success probability |
| :------------ | ---------------------: |  ----------------------: |
| ML-KEM-512    |                  0.49  |                     0.45 |
| ML-KEM-768    |                  0.29  |                     0.25 |
| ML-KEM-1024   |                  0.53  |                     0.47 |
{: #fast-succ-prob title="Success probabilities for faster Kemeleon encoding"}

## Summary of Encodings

| Algorithm / Parameter    | Output size (bytes)  | Success probability  | Additional considerations |
| :----------------------- | -------------------: | -------------------: | ------------------------: |
| Kemeleon - ML-KEM512     | pk: 781, ctxt: 877   | pk: 0.56, ctxt: 0.51 | Large int (750B) arithmetic |
| Kemeleon - ML-KEM768     | pk: 1156, ctxt: 1252 | pk: 0.83, ctxt: 0.77 | Large int (1150B) arithmetic |
| Kemeleon - ML-KEM1024    | pk: 1530, ctxt: 1658 | pk: 0.62, ctxt: 0.57 | Large int (1500B) arithmetic |
| :----------------------- | -------------------: | -------------------: | ------------------------: |
| KemeleonNR - ML-KEM512   | pk: 797, ctxt: 893   | pk: 1.00, ctxt: 1.00 |                           |
| KemeleonNR - ML-KEM768   | pk: 1172, ctxt: 1268 | pk: 1.00, ctxt: 1.00 |                           |
| KemeleonNR - ML-KEM1024  | pk: 1546, ctxt: 1674 | pk: 1.00, ctxt: 1.00 |                           |
| :----------------------- | -------------------: | -------------------: | ------------------------: |
| KemeleonFT - ML-KEM512   | pk: 781, ctxt: 877   | pk: 0.49, ctxt: 0.45 | Smaller int (235B) arithmetic |
| KemeleonFT - ML-KEM768   | pk: 1156, ctxt: 1252 | pk: 0.29, ctxt: 0.25 | Smaller int (355B) arithmetic |
| KemeleonFT - ML-KEM1024  | pk: 1530, ctxt: 1658 | pk: 0.53, ctxt: 0.47 | Smaller int (475B) arithmetic |
{: #summary-encoding title="Summary of Kemeleon Variants, NR = No Reject, FT = Faster"}


# Security Considerations

This section contains additional security considerations about the Kemeleon encodings described in this document.

In general, the obfuscation properties of the Kemeleon encodings depend on module LWE assumptions similar to those underlying the IND-CCA security of ML-KEM; see {{GSV24}} for the detailed security analysis of the original Kemeleon encoding.

## Randomness Sampling
Both public key and ciphertext encodings in the original Kemeleon encoding are randomized.
The randomness (or seed used to generate randomness) used in Kemeleon encodings MUST be kept secret.
In particular, public randomness enables distinguishing a Kemeleon-encoded value from a random bytestring:
Decoding the value in question and re-encoding it with the public randomness will yield the original value if it was Kemeleon-encoded.

## Timing Side-Channels
Beyond timing side-channel considerations for ML-KEM itself, care should be taken when using Kemeleon encodings, in particular those with a non-zero failure probability.
Rejecting and re-generating public keys or ciphertexts may leak information about the use of Kemeleon encodings, as might the overhead of the encoding itself.

# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments

TODO acknowledge.
