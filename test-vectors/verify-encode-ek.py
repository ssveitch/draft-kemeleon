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
"""Verify the Kemeleon EncodeEk and DecodeEk test-vector corpus."""

import json
import re
from collections import Counter
from pathlib import Path


Q = 3329
N = 256
B = 2996
Q_N = Q**N
POLY_BYTES = 384
RHO_BYTES = 32
PARAMETERS = {
    "ML-KEM-768": 3,
    "ML-KEM-1024": 4,
}
HEX_BYTES = re.compile(r"(?:[0-9a-f]{2})*")
HEX_INTEGER = re.compile(r"(?:0|[1-9a-f][0-9a-f]*)")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_bytes(value: object, label: str, length: int | None = None) -> bytes:
    require(isinstance(value, str), f"{label}: expected a hexadecimal string")
    require(HEX_BYTES.fullmatch(value) is not None, f"{label}: non-canonical hex")
    decoded = bytes.fromhex(value)
    if length is not None:
        require(len(decoded) == length, f"{label}: expected {length} bytes")
    return decoded


def parse_integer(value: object, label: str) -> int:
    require(isinstance(value, str), f"{label}: expected a hexadecimal string")
    require(HEX_INTEGER.fullmatch(value) is not None, f"{label}: non-canonical hex")
    return int(value, 16)


def byte_decode_12(encoded: bytes) -> list[int]:
    """FIPS 203 ByteDecode_12 for one polynomial."""
    require(len(encoded) == POLY_BYTES, "ByteDecode_12: incorrect polynomial length")
    value = int.from_bytes(encoded, "little")
    coefficients = [(value >> (12 * i)) & 0xFFF for i in range(N)]
    require(
        all(coefficient < Q for coefficient in coefficients),
        "ByteDecode_12: non-canonical coefficient",
    )
    return coefficients


def byte_encode_12(coefficients: list[int]) -> bytes:
    """FIPS 203 ByteEncode_12 for one polynomial."""
    require(len(coefficients) == N, "ByteEncode_12: incorrect coefficient count")
    require(
        all(0 <= coefficient < Q for coefficient in coefficients),
        "ByteEncode_12: coefficient outside Z_q",
    )
    value = sum(coefficient << (12 * i) for i, coefficient in enumerate(coefficients))
    return value.to_bytes(POLY_BYTES, "little")


def accumulate(coefficients: list[int]) -> int:
    """Return sum(coefficients[i] * Q**i)."""
    value = 0
    for coefficient in reversed(coefficients):
        value = value * Q + coefficient
    return value


def vector_decode(encoded: bytes) -> list[int]:
    value = int.from_bytes(encoded, "little") % Q_N
    coefficients = []
    for _ in range(N):
        coefficients.append(value % Q)
        value //= Q
    return coefficients


def decode_ek(eek: bytes, k: int, field_bytes: int) -> bytes:
    body = b"".join(
        byte_encode_12(vector_decode(eek[i * field_bytes : (i + 1) * field_bytes]))
        for i in range(k)
    )
    return body + eek[-RHO_BYTES:]


def verify_vector(vector: dict) -> str:
    name = vector["name"]
    require(isinstance(name, str) and name, "vector name must be nonempty")
    require(vector["kem"] in PARAMETERS, f"{name}: unknown ML-KEM parameter set")
    k = PARAMETERS[vector["kem"]]
    require(vector["k"] == k, f"{name}: incorrect k")

    t = vector["t"]
    require(isinstance(t, int), f"{name}: t must be an integer")
    require(t >= 76 and (t - 76) % 8 == 0, f"{name}: invalid t")
    require((B + t) % 8 == 0, f"{name}: field is not byte-aligned")
    field_bytes = (B + t) // 8
    require(vector["field_bytes"] == field_bytes, f"{name}: incorrect field length")
    require(
        vector["encoded_body_bytes"] == k * field_bytes,
        f"{name}: incorrect encoded body length",
    )
    require(
        vector["encoded_ek_bytes"] == k * field_bytes + RHO_BYTES,
        f"{name}: incorrect encoded key length",
    )

    ek = parse_bytes(vector["ek"], f"{name}.ek", k * POLY_BYTES + RHO_BYTES)
    eek = parse_bytes(vector["eek"], f"{name}.eek", vector["encoded_ek_bytes"])
    require(decode_ek(eek, k, field_bytes) == ek, f"{name}: DecodeEk mismatch")
    require(eek[-RHO_BYTES:] == ek[-RHO_BYTES:], f"{name}: rho mismatch")

    if "m" not in vector:
        require(
            "d" not in vector and "z" not in vector,
            f"{name}: decode-only vector contains key-generation inputs",
        )
        return "decode-only"

    parse_bytes(vector["d"], f"{name}.d", 32)
    parse_bytes(vector["z"], f"{name}.z", 32)
    require(isinstance(vector["m"], list), f"{name}: m must be an array")
    require(len(vector["m"]) == k, f"{name}: incorrect m count")

    expected_fields = []
    for i, encoded_m in enumerate(vector["m"]):
        coefficients = byte_decode_12(ek[i * POLY_BYTES : (i + 1) * POLY_BYTES])
        residue = accumulate(coefficients)
        m = parse_integer(encoded_m, f"{name}.m[{i}]")
        max_m = (2 ** (B + t) - 1 - residue) // Q_N
        require(0 <= m <= max_m, f"{name}: m[{i}] outside the sampling bound")
        encoded = (residue + m * Q_N).to_bytes(field_bytes, "little")
        expected_fields.append(encoded)

    require(
        b"".join(expected_fields) + ek[-RHO_BYTES:] == eek,
        f"{name}: EncodeEk mismatch",
    )
    return "encode"


def main() -> None:
    path = Path(__file__).with_name("encode-ek.json")
    document = json.loads(path.read_text())
    counts = Counter()
    names = set()

    for vector in document["vectors"]:
        require(vector["name"] not in names, f"duplicate vector name: {vector['name']}")
        names.add(vector["name"])
        kind = verify_vector(vector)
        counts[(vector["kem"], vector["t"], kind)] += 1

    expected = Counter(
        {
            ("ML-KEM-768", 132, "encode"): 3,
            ("ML-KEM-768", 132, "decode-only"): 3,
            ("ML-KEM-1024", 76, "encode"): 3,
            ("ML-KEM-1024", 76, "decode-only"): 3,
            ("ML-KEM-1024", 132, "encode"): 3,
            ("ML-KEM-1024", 132, "decode-only"): 3,
        }
    )
    require(counts == expected, f"unexpected profile/count map: {counts}")
    print(f"verified {len(names)} EncodeEk/DecodeEk vectors across 3 profiles")


if __name__ == "__main__":
    main()
