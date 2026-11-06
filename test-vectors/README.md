# EncodeEk and DecodeEk test vectors

`encode-ek.json` contains deterministic test vectors for the non-rejection
`Kemeleon.EncodeEk` and `Kemeleon.DecodeEk` algorithms. The integer fields use
the little-endian byte encoding proposed in
[PR #20](https://github.com/ssveitch/draft-kemeleon/pull/20).

The vectors cover these profiles:

| ML-KEM parameter set | `t` | Polynomials | Field bytes | Encoded key bytes |
| --- | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 76 | 2 | 384 | 800 |
| ML-KEM-768 | 76 | 3 | 384 | 1184 |
| ML-KEM-1024 | 76 | 4 | 384 | 1568 |
| ML-KEM-1024 | 132 | 4 | 391 | 1596 |
| ML-KEM-768 | 132 | 3 | 391 | 1205 |

Each profile has three encoding vectors and three decode-only vectors:

- an ML-KEM ACVP key-generation case with pseudorandom `m` values;
- a deterministic ML-KEM key with `m = 0`;
- a deterministic ML-KEM key with the maximum valid `m` for each polynomial;
- all-`ff`, all-`00`, and pseudorandom encoded inputs that exercise total
  decoding independently of `EncodeEk`.

Encoding vectors list the `m` value used for each polynomial, allowing an
implementation to test a deterministic form of `EncodeEk`. Production
implementations must sample `m` uniformly with cryptographically secure
randomness. The listed values are solely for deterministic testing and do not
define an additional wire field or RNG construction.

Each `m` is a hexadecimal integer written most significant digit first (for
example, Python's `int(m, 16)`), unlike the integer fields in `eek`, which are
little-endian byte strings.

Each encoding vector also lists `m_max`, the inclusive per-polynomial bound
`floor((2^(2996+t) - 1 - r_i) / q^256)`, using the same hexadecimal-integer
notation as `m`. This is expected test metadata, not an additional wire field.
The verifier checks these bounds and requires both possible branches, `g` and
`g - 1`, at both `t = 76` and `t = 132`, where
`g = floor((2^(2996+t) - 1) / q^256)`.
In the `t = 76` ACVP tcId 51 vector, polynomial index 1 (zero-based) has bound
`g - 1`, while the other three have bound `g`.

Run the dependency-free verifier (Python 3.10 or later) with:

```sh
python3 test-vectors/verify-encode-ek.py
```

## Reproducing the decode-prng inputs

These are deterministic test inputs, not a production RNG. There is no separate
seed and `d`/`z` are not used. For each profile, use the exact ASCII label:

- `ML-KEM-1024|t76|decode-prng`
- `ML-KEM-1024|t132|decode-prng`
- `ML-KEM-768|t132|decode-prng`
- `ML-KEM-512|t76|decode-prng`
- `ML-KEM-768|t76|decode-prng`

Block `c` is `SHA-256(UTF-8(label + "|" + decimal(c)))`. The counter starts at
zero and uses unpadded decimal ASCII, without a length prefix or terminator.
There is no fixed-width binary counter or counter byte order. Concatenate blocks
in order and retain the first `npk` bytes:

| Profile | `npk` | Stream truncation | Final 32-byte `rho` |
| --- | ---: | --- | --- |
| ML-KEM-512, t=76 | 800 | Blocks 0 through 24 | Block 24 |
| ML-KEM-768, t=76 | 1184 | Blocks 0 through 36 | Block 36 |
| ML-KEM-1024, t=76 | 1568 | Blocks 0 through 48 | Block 48 |
| ML-KEM-1024, t=132 | 1596 | Blocks 0 through 48, then first 28 bytes of block 49 | Last 4 bytes of block 48, then first 28 bytes of block 49 |
| ML-KEM-768, t=132 | 1205 | Blocks 0 through 36, then first 21 bytes of block 37 | Last 11 bytes of block 36, then first 21 bytes of block 37 |

The original PQPAKE input used network-order polynomial fields. To reproduce
this corpus, reverse each of the first `k` polynomial fields separately, each
of width `(2996 + t) / 8` bytes, and leave the final 32-byte `rho` unchanged.
The decoded `ek` is unchanged. The stream generates `rho` along with the rest
of the input; no separate `rho` generation step is applied.

Run the standalone standard-library reproduction check with:

```sh
python3 test-vectors/repro-decode-prng.py
```

It checks all five full `eek` values, stream SHA-256 digests, `rho`, decoded
keys, and a negative control that starts the counter at 1 and must not match.
Optionally pass `--original PATH` to also check the original attached corpus
and its raw-file SHA-256 digest for the three profiles it contains. The two
new `t=76` profiles are not attributed to that original attachment.
This does not regenerate or overwrite files.

The encapsulation keys in the ACVP cases are independently checkable from the
listed `d` and `z` inputs using FIPS 203 Algorithm 16. They are from NIST's
[`ML-KEM-keyGen-FIPS203/internalProjection.json`](https://github.com/usnistgov/ACVP-Server/blob/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json)
at commit `975de31eb83d87039ec88934fdc47d8c312b892d`: ML-KEM-512 uses
`tgId=1`, `tcId=1`; ML-KEM-768 uses `tgId=2`, `tcId=26`; and ML-KEM-1024
uses `tgId=3`, `tcId=51`. See [the retained NIST source notice](NIST-NOTICE.md).

## Reproducing the additional t=76 profiles

The ML-KEM-512 and ML-KEM-768 `t=76` profiles each use their listed ACVP key
for all three encoding cases, including zero and maximal `m`. The original
profiles retain their patterned keys and all original vector values unchanged.
For each new random-`m` case, polynomial index `i` is zero-based and:

```text
h_i = SHA-256(UTF-8(kem + "|t76|m-random|" + decimal(i)))
m_i = OS2IP_big_endian(h_i) mod (m_max[i] + 1)
```

Here `kem` is exactly `ML-KEM-512` or `ML-KEM-768`. This deterministic,
modulo-reduced choice is solely for fixtures: it is not uniform sampling and
must not be used as a production RNG. The zero/max cases use the corresponding
boundaries; decode-only inputs are `ff`, `00`, or the documented counter stream.
Given the pinned NIST `internalProjection.json` file, print the twelve added
vectors without overwriting the corpus:

```sh
python3 test-vectors/generate-t76-followup.py PATH/TO/internalProjection.json
```

The original eighteen vectors were adapted from the
[`draft-vos-cfrg-pqpake` test-vector contribution](https://github.com/chris-wood/draft-pqpake/issues/51#issuecomment-6073244196).
It has been recomputed for the little-endian fields specified by
[`draft-kemeleon` PR #20 at commit `63dfd77`](https://github.com/ssveitch/draft-kemeleon/commit/63dfd776cecd2f569a087b318fea6f2cd3e0a201)
and is checked from the ML-KEM polynomial encoding by the verifier in this
directory. The twelve additional cases extend default `t=76` coverage to the
remaining ML-KEM parameter sets. The complete corpus contains thirty cases
across five profiles, not every possible value of Kemeleon's parameter `t`.
