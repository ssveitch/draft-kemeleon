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
    organization: IBM Research - Zurich
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

  FIPS203:
    target: https://doi.org/10.6028/NIST.FIPS.203
    title: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    seriesinfo:
      "NIST": "FIPS 203"
    date: August 2024
   RFC9380:

informative:

   OBFS4:
    title: obfs4 (The obfourscator)
    target: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/blob/HEAD/doc/obfs4-spec.txt

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

--- abstract

This document specifies algorithms for encoding ML-KEM public keys and ciphertexts as random bytestrings.
Kemeleon encodings provide obfuscation of public keys and ciphertexts, relying on module LWE assumptions.
This document specifies a number of variants of these encodings, with differing rejection rates and output sizes.

--- middle

# Introduction

ML-KEM {{FIPS203}} is a post-quantum key-encapsulation mechanism (KEM) recently standardized by NIST,
Many applications are transitioning from classical Diffie-Hellman (DH) based solutions to constructions based on ML-KEM.
Meanwhile, the use of Elligator and related Hash-to-Curve {{RFC9380}} algorithms are ubiquitous in DH-based protocols where DH shares are required to be encoded as random bytestrings.
For example, applications using Elligator include protocols used for censorship circumvention in Tor {{OBFS4}}, password-authenticated key exchange (PAKE) protocols {{!CPACE=I-D.irtf-cfrg-cpace}} {{?OPAQUE=I-D.irtf-cfrg-opaque}}, private set intersection (PSI) {{?ECDH-PSI=I-D.ecdh-psi}}, and more.

In the KEM-based setting, an analogous encoding for KEM public keys and ciphertexts to random bytestrings is required.
This document specifies such an encoding, namely Kemeleon, for ML-KEM public keys and ciphertexts.
The construction originates from {{GSV24}}, where the encoding was required for a post-quantum obfuscated KEM construction.
Beyond the default construction, this document additionally specifies variants that allow for a deterministic encoding, avoid rejection sampling, and avoid larger integer computations.
Aside from these variants, it is notable that the public key encoding results in smaller public key representations than in the current specification of ML-KEM.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Notation / ML-KEM Background


A KEM consists of three algorithms:

- 'KeyGen() -> (ek, dk)': A probabilistic key generation algorithm that, with no input, generates a public (encapsulation) key 'ek' and a secret (decapsulation) key 'dk'.
- 'Encaps(ek) -> (c, K)': A probabilistic encapsulation algorithm that takes as input a public key 'ek', and outputs a ciphertext 'ct' and shared secret key 'K'.
- 'Decaps(dk, c) -> K': A decapsulation algorithm that takes as input a secret key 'dk' and ciphertext 'c', and outputs a shared secret key 'K'.

TODO:
* ML-KEM specifics (q, compress, decompress, ...)

`ML-KEM.KeyGen()` (Section 7.1 {{FIPS203}}) produces a public key, `ek`, (termed an encapsulation key in {{FIPS203}}) and a private key, `dk`, (decapsulation key).
Public keys consist of byte-encoded vectors of coefficients in Z_q, where each coefficient is encoded in 12 bits, together with a 32-byte seed for generating the matrix `A`.
`ML-KEM.Encaps(ek)` (Section 7.2 {{FIPS203}}) produces ciphertexts consisting of byte-encoded compressed vectors of cofficients, where each coefficient in Z_q is compressed by a certain number of bits (depending on the ML-KEM parameter set).

The following terms and notation are used throughout this document:

- `msb(x)` refers to the most significant bit of the value x
- `a[i]` denotes the `i`th position of a vector `a` of coefficients
- `concat(x0, ..., xN)`: returns the concatenation of bytestrings.

# Kemeleon encoding

At a high level, the constructions in this document instantiate the following functions:

- `EncodePk(ek) -> eek` is the (possibly randomized) encoding algorithm that on input a public key, outputs an obfuscated public key or an error.
- `DecodePk(eek) -> ek` is the deterministic decoding algorithm that on input an obfuscated public key, outputs a public key.
- `EncodeCtxt(c) -> ec` is the (possibly randomized) encoding algorithm that on input a ciphertext, outputs an obfuscated ciphertext or an error.
- `DecodeCtxt(ec) -> c` is the deterministic decoding algorithm that on input an obfuscated ciphertext, outputs a ciphertext.

## Common functions

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
      t = 0
      for j from 1 to i-1:
         t += a[j]
      a[i] = (r - t)/(q^(i-1)) % q
   return a
~~~

The following algorithm recovers randomness from a compressed ciphertext coefficient.
The mapping is based on the `Compress_d`, `Decompress_d` algorithms from (Section 4.2.1 {{FIPS203}}).

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

## Encoding public keys

~~~
Kemeleon1.EncodePk(ek = (t, rho)):
   r = VectorEncode(t)
   if r == err:
      return err
   else:
      return concat(r,rho)
~~~

~~~
Kemeleon1.DecodePk(eek):
   r,rho = eek // rho is fixed lenght
   t = VectorDecode(r)
   return (t, rho)
~~~

## Encoding ciphertexts

TODO: complete

~~~
Kemeleon1.EncodeCtxt(c = (c_1,c_2)):
   u = Decompress_d(c_1,d_u)
   for i from 1 to k*n:
      x = RecoverFrom_d(u[i],c[i])
~~~


## Deterministic variant

## Faster arithmetic variant

## Non-rejection sampling variant

## Summary of encodings

| Algorithm       | pk size (bytes) | ct size (bytes) | Success probability | Additional considerations |
| :-------------- | --------------: | --------------: | ------------------: | ------------------------: |
| Kemeleon1-512   |                 |                 |                     |                           |

# Obfuscated KEMs

This section describes how to use the above specified encoding algorithms in conjunction with a KEM to produce an obfuscated KEM {{GSV24}}.


# Security Considerations

This section contains additional security considerations about the Kemeleon encodings described in this document.

## Randomness sampling
Both public key and ciphertext encodings in the original Kemeleon encoding are randomized.
The randomness (or seed used to generate randomness) MUST NOT be derived from a public source.
For public key encodings, randomness can be stored with the respective secret key.
In particular, using a public source of randomness would reveal ...

## Timing side-channels
(also from resampling)


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments

TODO acknowledge.