# EncodeEk and DecodeEk test vectors

`encode-ek.json` contains deterministic test vectors for the non-rejection
`Kemeleon.EncodeEk` and `Kemeleon.DecodeEk` algorithms. The integer fields use
the little-endian byte encoding proposed in
[PR #20](https://github.com/ssveitch/draft-kemeleon/pull/20).

The vectors cover these profiles:

| ML-KEM parameter set | `t` | Polynomials | Field bytes | Encoded key bytes |
| --- | ---: | ---: | ---: | ---: |
| ML-KEM-1024 | 76 | 4 | 384 | 1568 |
| ML-KEM-1024 | 132 | 4 | 391 | 1596 |
| ML-KEM-768 | 132 | 3 | 391 | 1205 |

Each profile has three encoding vectors and three decode-only vectors:

- an ML-KEM ACVP key-generation case with pseudorandom `m` values;
- a patterned ML-KEM key with `m = 0`;
- a patterned ML-KEM key with the maximum valid `m` for each polynomial;
- all-`ff`, all-`00`, and pseudorandom encoded inputs that exercise total
  decoding independently of `EncodeEk`.

Encoding vectors list the `m` value used for each polynomial, allowing an
implementation to test a deterministic form of `EncodeEk`. Production
implementations must sample `m` uniformly with cryptographically secure
randomness. The listed values are solely for deterministic testing and do not
define an additional wire field or RNG construction.

Run the dependency-free verifier with:

```sh
python3 test-vectors/verify-encode-ek.py
```

The encapsulation keys in the ACVP cases are independently checkable from the
listed `d` and `z` inputs using FIPS 203 Algorithm 16. They are from NIST's
[`ML-KEM-keyGen-FIPS203/internalProjection.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json)
at commit `975de31eb83d87039ec88934fdc47d8c312b892d`: ML-KEM-768 uses
`tgId=2`, `tcId=26`, and ML-KEM-1024 uses `tgId=3`, `tcId=51`.

The vector corpus was adapted from the
[`draft-vos-cfrg-pqpake` test-vector contribution](https://github.com/chris-wood/draft-pqpake/issues/51#issuecomment-6073244196).
It has been recomputed for the little-endian fields specified by
[`draft-kemeleon` PR #20 at commit `63dfd77`](https://github.com/ssveitch/draft-kemeleon/commit/63dfd776cecd2f569a087b318fea6f2cd3e0a201)
and is checked from the ML-KEM polynomial encoding by the verifier in this
directory. This corpus focuses on the ML-KEM parameter sets and `t` values used
by PQPAKE, plus ML-KEM-1024 at Kemeleon's default `t=76`; it does not attempt to
cover every ML-KEM parameter set.
