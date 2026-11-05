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
"""Reproduce the five fixed decode-prng inputs, with a negative control."""

import argparse
import hashlib
import json
from pathlib import Path


ORIGINAL_SHA256 = "3d267fdf7352fa8fe6d9f269872f511ac95fe04a8fb63568baef9071bb38ffcc"
PROFILES = (
    ("ML-KEM-512", 76, 2,
     "8b3ba40362b75821d311cdd703d09783a9b50ec12a7a85e595ce7a897d9db4a8",
     "6081b330abe07e5a2c9341fc1b28c3c2387cee89cbb323db149e0483ea943631"),
    ("ML-KEM-768", 76, 3,
     "a946611e5c2840eb1e2aeb186f5ce6ea621f0a700c18e3197aed1b466816c6d8",
     "ffd999532e0543a67b4444105e33505b4aecf84667252f2acdecf9c245179a9a"),
    ("ML-KEM-1024", 76, 4,
     "b4cfcf042c23eba40f369069ebd5796b905516faf9ce9ed14aa07664802d0aa2",
     "caa6e16325c9622f0c71ca6a93562d4a3c8aa4668d62c0d7a6fb38164d862e8c"),
    ("ML-KEM-1024", 132, 4,
     "1fadbbec50614a71181d8196dd5f4d723a3d5b49f4256292ac5f090133a43dbb",
     "268ae40f4c57835172f358fde3f6cc12d90cd0c4abc79077cfa507c837bccb08"),
    ("ML-KEM-768", 132, 3,
     "f7f1211e9cf85bc639ac57f2afb9fb846ab77d684c841b5e462878911b0cdcfc",
     "1c8bc835e9fc99968995e721440ef6a0beacfb20f5a2db52421fc8c2b2747131"),
)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def equal(label, actual, expected):
    if actual == expected:
        return
    offset = next((i for i, pair in enumerate(zip(actual, expected))
                   if pair[0] != pair[1]), min(len(actual), len(expected)))
    raise SystemExit(
        f"FAIL {label}: first difference at byte {offset}; "
        f"actual={actual[offset:offset+1].hex() or '<EOF>'}, "
        f"expected={expected[offset:offset+1].hex() or '<EOF>'}; "
        f"lengths={len(actual)}/{len(expected)}")


def stream(label, length, start=0):
    blocks = (hashlib.sha256(f"{label}|{c}".encode("utf-8")).digest()
              for c in range(start, start + (length + 31) // 32))
    return b"".join(blocks)[:length]


def reverse_fields(encoded, k, width):
    return b"".join(encoded[i * width:(i + 1) * width][::-1]
                    for i in range(k)) + encoded[k * width:]


def decode_key(encoded, k, width):
    body = bytearray()
    for i in range(k):
        value = int.from_bytes(encoded[i * width:(i + 1) * width], "little") % (3329 ** 256)
        packed = 0
        for j in range(256):
            value, coefficient = divmod(value, 3329)
            packed |= coefficient << (12 * j)
        body.extend(packed.to_bytes(384, "little"))
    return bytes(body) + encoded[-32:]


def find(document, name):
    matches = [v for v in document["vectors"] if v["name"] == name]
    require(len(matches) == 1, f"FAIL {name}: expected exactly one vector")
    return matches[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vectors", type=Path,
                        default=Path(__file__).with_name("encode-ek.json"))
    parser.add_argument("--original", type=Path,
                        help="optional original big-endian kemeleon-ek.json")
    args = parser.parse_args()
    current = json.loads(args.vectors.read_bytes())
    original = None
    if args.original:
        raw = args.original.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == ORIGINAL_SHA256,
                f"FAIL original file SHA-256: actual={digest}, expected={ORIGINAL_SHA256}")
        original = json.loads(raw)
        print(f"PASS original file SHA-256: {digest}")
    controls = 0
    for kem, t, k, expected_hash, expected_rho in PROFILES:
        name = f"{kem.lower().replace('ml-kem', 'mlkem')}-t{t}-decode-prng"
        label = f"{kem}|t{t}|decode-prng"
        width = (2996 + t) // 8
        length = k * width + 32
        vector = find(current, name)
        has_original = original is not None and any(v["name"] == name for v in original["vectors"])
        require((vector["kem"], vector["t"], vector["k"], vector["field_bytes"],
                 vector["encoded_ek_bytes"]) == (kem, t, k, width, length),
                f"FAIL {name}: profile metadata differs")
        raw = stream(label, length)
        require(hashlib.sha256(raw).hexdigest() == expected_hash,
                f"FAIL {name}: original-stream SHA-256 differs")
        equal(f"{name} rho", raw[-32:], bytes.fromhex(expected_rho))
        encoded = reverse_fields(raw, k, width)
        equal(f"{name} PR eek", encoded, bytes.fromhex(vector["eek"]))
        equal(f"{name} decoded ek", decode_key(encoded, k, width), bytes.fromhex(vector["ek"]))
        if has_original:
            old = find(original, name)
            equal(f"{name} original eek", raw, bytes.fromhex(old["eek"]))
            equal(f"{name} unchanged ek", bytes.fromhex(old["ek"]), bytes.fromhex(vector["ek"]))
        print(f"PASS {name}: {length} bytes; stream hash, rho, PR eek, decoded ek"
              + (", original eek and unchanged ek" if has_original else ""))
        wrong = stream(label, length, start=1)
        require(reverse_fields(wrong, k, width) != bytes.fromhex(vector["eek"]),
                f"FAIL {name}: wrong counter unexpectedly matched PR eek")
        controls += 1
        if has_original:
            require(wrong != bytes.fromhex(find(original, name)["eek"]),
                    f"FAIL {name}: wrong counter unexpectedly matched original eek")
            controls += 1
        print(f"PASS negative control {name}: counter start=1 does not match")
    print(f"PASS all {len(PROFILES)} constructions; {controls} wrong-counter comparisons rejected")


if __name__ == "__main__":
    main()
