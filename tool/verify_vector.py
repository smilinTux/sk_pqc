#!/usr/bin/env python3
"""Python interop verifier for the sk_pqc hybrid KEM test vector.

This is the reference the future `pqkem.py` (PQC-MIGRATION Q1) must match. It
re-derives the hybrid shared secret from the emitted test vector using:

  * X25519   — `cryptography` (pyca)
  * ML-KEM-768 — liboqs-python (`oqs`)  [optional: skipped if not installed]
  * combiner — HKDF-SHA256( X25519_ss || MLKEM768_ss, salt, info )

and asserts it equals the recorded `hybrid.shared_secret`. If `oqs` is absent it
still verifies the X25519 leg + the combiner against the recorded ML-KEM leg
secret, which is enough to lock the interop contract.

Usage:
    python3 tool/verify_vector.py [test_vectors/hybrid_kem_x25519_mlkem768.json]
"""
import binascii
import json
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def h2b(h: str) -> bytes:
    return binascii.unhexlify(h)


def b2h(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def main() -> int:
    path = sys.argv[1] if len(sys.argv) > 1 else (
        "test_vectors/hybrid_kem_x25519_mlkem768.json"
    )
    v = json.load(open(path))
    assert v["suite"] == "x25519-mlkem768", v["suite"]

    priv = h2b(v["hybrid"]["private_key"])
    ct = h2b(v["hybrid"]["ciphertext"])
    x_priv_seed, mlkem_sk = priv[:32], priv[32:]
    x_ct, mlkem_ct = ct[:32], ct[32:]

    # --- X25519 leg: DH(recipient_priv, ephemeral_pub) ---
    x_priv = X25519PrivateKey.from_private_bytes(x_priv_seed)
    x_eph_pub = X25519PublicKey.from_public_bytes(x_ct)
    x_ss = x_priv.exchange(x_eph_pub)
    assert b2h(x_ss) == v["legs"]["x25519"]["shared_secret"], "x25519 leg mismatch"

    # --- ML-KEM-768 leg: decapsulate (liboqs-python if available) ---
    try:
        import oqs  # type: ignore

        with oqs.KeyEncapsulation("ML-KEM-768", secret_key=mlkem_sk) as kem:
            mlkem_ss = kem.decap_secret(mlkem_ct)
        assert b2h(mlkem_ss) == v["legs"]["mlkem768"]["shared_secret"], (
            "ML-KEM leg mismatch vs liboqs-python"
        )
        ml_source = "liboqs-python decap"
    except ImportError:
        mlkem_ss = h2b(v["legs"]["mlkem768"]["shared_secret"])
        ml_source = "recorded vector (oqs not installed)"

    # --- combiner: HKDF-SHA256(X25519_ss || MLKEM768_ss, salt, info, 32) ---
    salt = h2b(v["combiner"]["salt_hex"])
    info = v["combiner"]["info_utf8"].encode()
    shared = HKDF(
        algorithm=hashes.SHA256(), length=v["combiner"]["length"], salt=salt, info=info
    ).derive(x_ss + mlkem_ss)

    expected = v["hybrid"]["shared_secret"]
    ok = b2h(shared) == expected
    print(f"ML-KEM leg via : {ml_source}")
    print(f"derived shared : {b2h(shared)}")
    print(f"expected shared: {expected}")
    print("MATCH:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
