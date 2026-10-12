"""Writes the password-protected Bitwarden export fixtures of vault-interop.

The encryption is an independent implementation, in Python with the `cryptography` and
`argon2-cffi` packages, of the format Bitwarden writes: the master key from PBKDF2-HMAC-SHA256 or
Argon2id (over the SHA-256 of the salt), the encryption and MAC keys from HKDF-Expand with the
info strings `enc` and `mac`, and `2.<iv>|<ciphertext>|<mac>` strings with AES-256-CBC, PKCS#7
padding, and HMAC-SHA256 over the IV and ciphertext.

Each fixture encrypts `full.json` under the password `correct horse battery staple`. The IVs and
salts are derived from fixed labels, so the output is the same on every run.

Usage, from the repository root:

    pip install -r tools/bitwarden-fixtures/requirements.txt
    python3 -I tools/bitwarden-fixtures/generate.py crates/vault-interop/tests/fixtures
"""

import base64
import hashlib
import hmac
import json
import pathlib
import sys

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PASSWORD = "correct horse battery staple"
VALIDATION = "5a0d8f3e-2b7c-4e1a-9f6d-3c8b1a2e4d70"


def fixed(label: str, n: int) -> bytes:
    return hashlib.sha256(label.encode()).digest()[:n]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def master_key(salt: str, kdf: dict) -> bytes:
    if kdf["kdfType"] == 0:
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode(),
            iterations=kdf["kdfIterations"],
        ).derive(PASSWORD.encode())
    return hash_secret_raw(
        secret=PASSWORD.encode(),
        salt=hashlib.sha256(salt.encode()).digest(),
        time_cost=kdf["kdfIterations"],
        memory_cost=kdf["kdfMemory"] * 1024,
        parallelism=kdf["kdfParallelism"],
        hash_len=32,
        type=Type.ID,
    )


def expand(key: bytes, info: bytes) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info).derive(key)


def enc_string(enc: bytes, mac: bytes, iv: bytes, plaintext: bytes) -> str:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    tag = hmac.new(mac, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(tag)}"


def protected(name: str, plain: bytes, kdf: dict) -> dict:
    salt = b64(fixed(name + " salt", 16))
    key = master_key(salt, kdf)
    enc, mac = expand(key, b"enc"), expand(key, b"mac")
    return {
        "encrypted": True,
        "passwordProtected": True,
        "salt": salt,
        **kdf,
        "encKeyValidation_DO_NOT_EDIT": enc_string(
            enc, mac, fixed(name + " validation iv", 16), VALIDATION.encode()
        ),
        "data": enc_string(enc, mac, fixed(name + " data iv", 16), plain),
    }


def main() -> None:
    out = pathlib.Path(sys.argv[1])
    plain = (out / "full.json").read_bytes()
    fixtures = {
        "protected-pbkdf2.json": {
            "kdfType": 0,
            "kdfIterations": 5000,
            "kdfMemory": None,
            "kdfParallelism": None,
        },
        "protected-argon2id.json": {
            "kdfType": 1,
            "kdfIterations": 2,
            "kdfMemory": 16,
            "kdfParallelism": 2,
        },
    }
    for name, kdf in fixtures.items():
        doc = protected(name, plain, kdf)
        (out / name).write_text(json.dumps(doc, indent=2) + "\n")


if __name__ == "__main__":
    main()
