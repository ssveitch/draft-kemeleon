#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) 2026 IETF Trust and the persons identified as authors of the
# code. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, is permitted pursuant to, and subject to the license terms
# contained in, the Revised BSD License set forth in Section 4.c of the IETF
# Trust's Legal Provisions Relating to IETF Documents
# (https://trustee.ietf.org/license-info).
"""Print twelve t=76 follow-up vectors from the pinned NIST ACVP JSON.

Pass the ML-KEM-keyGen-FIPS203/internalProjection.json file at ACVP-Server
commit 975de31eb83d87039ec88934fdc47d8c312b892d. No files are overwritten.
"""

import argparse
import hashlib
import json
from pathlib import Path


Q = 3329
Q_N = Q ** 256
WIDTH = 384


def stream(label, length):
    return b"".join(hashlib.sha256(f"{label}|{c}".encode("utf-8")).digest()
                    for c in range((length + 31) // 32))[:length]


def residue(poly):
    # Parse adjacent pairs directly from their three-byte FIPS 203 encoding.
    coefficients = []
    for offset in range(0, WIDTH, 3):
        x, y, z = poly[offset:offset + 3]
        coefficients.extend((x | ((y & 15) << 8), (y >> 4) | (z << 4)))
    if any(a >= Q for a in coefficients):
        raise ValueError("noncanonical ML-KEM coefficient")
    return sum(a * Q ** j for j, a in enumerate(coefficients))


def decode(encoded, k):
    out = bytearray()
    for i in range(k):
        r = int.from_bytes(encoded[i * WIDTH:(i + 1) * WIDTH], "little") % Q_N
        packed = 0
        for j in range(256):
            r, coefficient = divmod(r, Q)
            packed |= coefficient << (12 * j)
        out.extend(packed.to_bytes(WIDTH, "little"))
    return bytes(out) + encoded[-32:]


def generate(kem, k, case):
    prefix = kem.lower().replace("ml-kem", "mlkem") + "-t76"
    length = k * WIDTH + 32
    ek = bytes.fromhex(case["ek"])
    if len(ek) != length:
        raise ValueError("incorrect ACVP key length")
    rs = [residue(ek[i * WIDTH:(i + 1) * WIDTH]) for i in range(k)]
    maxima = [(2 ** 3072 - 1 - r) // Q_N for r in rs]
    common = {"kem": kem, "k": k, "t": 76, "field_bytes": WIDTH,
              "encoded_body_bytes": k * WIDTH, "encoded_ek_bytes": length}
    vectors = []
    for mode in ("random", "zero", "max"):
        if mode == "random":
            ms = [int.from_bytes(hashlib.sha256(
                f"{kem}|t76|m-random|{i}".encode("utf-8")).digest(), "big")
                  % (maximum + 1) for i, maximum in enumerate(maxima)]
        else:
            ms = [0] * k if mode == "zero" else maxima
        eek = b"".join((r + m * Q_N).to_bytes(WIDTH, "little")
                       for r, m in zip(rs, ms)) + ek[-32:]
        note = (f"NIST ACVP tcId {case['tcId']}; " +
                {"random": "documented deterministic SHA-256-derived m values (test-only)",
                 "zero": "m = 0 for every polynomial",
                 "max": "m = m_max for every polynomial"}[mode])
        vectors.append({"name": f"{prefix}-acvp{case['tcId']}-m-{mode}", **common,
                        "note": note, "d": case["d"].lower(), "z": case["z"].lower(),
                        "m": [format(m, "x") for m in ms],
                        "m_max": [format(m, "x") for m in maxima],
                        "ek": ek.hex(), "eek": eek.hex()})
    for mode in ("ff", "00", "prng"):
        if mode == "prng":
            raw = stream(f"{kem}|t76|decode-prng", length)
            eek = b"".join(raw[i * WIDTH:(i + 1) * WIDTH][::-1]
                           for i in range(k)) + raw[-32:]
        else:
            eek = bytes.fromhex(mode) * length
        vectors.append({"name": f"{prefix}-decode-{mode}", **common,
                        "note": "decode only: fixed arbitrary input; see README for deterministic generation",
                        "ek": decode(eek, k).hex(), "eek": eek.hex()})
    return vectors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("acvp", type=Path)
    args = parser.parse_args()
    document = json.loads(args.acvp.read_bytes())
    vectors = []
    for kem, k, group_id, case_id in (("ML-KEM-512", 2, 1, 1), ("ML-KEM-768", 3, 2, 26)):
        groups = [g for g in document["testGroups"]
                  if g["parameterSet"] == kem and g["tgId"] == group_id]
        if len(groups) != 1:
            raise ValueError("missing ACVP group")
        cases = [c for c in groups[0]["tests"] if c["tcId"] == case_id]
        if len(cases) != 1:
            raise ValueError("missing ACVP case")
        vectors.extend(generate(kem, k, cases[0]))
    print(json.dumps(vectors, indent=2))


if __name__ == "__main__":
    main()
