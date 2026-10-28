"""
Secure File Encryption and Integrity Verification
AES-256-GCM + Scrypt + SHA-256
Educational project for authorised personal files only.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SFE1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
TAG_LEN = 16
AAD_PREFIX = b"SecureFileEncryption-v1"

def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    header = MAGIC + salt + nonce
    key = derive_key(password, salt)
    digest = hashlib.sha256(data).digest()
    # The digest is inside the authenticated ciphertext, not stored in plaintext.
    ciphertext = AESGCM(key).encrypt(nonce, digest + data, AAD_PREFIX + header)
    return header + ciphertext

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    minimum = len(MAGIC) + SALT_LEN + NONCE_LEN + TAG_LEN + 32
    if len(blob) < minimum or not blob.startswith(MAGIC):
        raise ValueError("Invalid or incomplete encrypted file.")
    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    header = blob[:offset]
    ciphertext = blob[offset:]
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, AAD_PREFIX + header)
    except Exception as exc:
        raise ValueError("Decryption failed: wrong password or file tampering detected.") from exc
    if len(plaintext) < 32:
        raise ValueError("Decrypted payload is incomplete.")
    expected_digest, data = plaintext[:32], plaintext[32:]
    if not hashlib.sha256(data).digest() == expected_digest:
        raise ValueError("Integrity verification failed.")
    return data

def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    data = input_path.read_bytes()
    output_path.write_bytes(encrypt_bytes(data, password))

def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    data = decrypt_bytes(input_path.read_bytes(), password)
    output_path.write_bytes(data)

def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt/decrypt a file and verify integrity.")
    sub = parser.add_subparsers(dest="command", required=True)
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input", type=Path)
    enc.add_argument("output", type=Path)
    enc.add_argument("--password", required=True, help="Demo password; do not use shell history for real secrets.")
    dec = sub.add_parser("decrypt", help="Decrypt and verify a file")
    dec.add_argument("input", type=Path)
    dec.add_argument("output", type=Path)
    dec.add_argument("--password", required=True, help="Demo password; do not use shell history for real secrets.")
    args = parser.parse_args()
    try:
        if args.command == "encrypt":
            encrypt_file(args.input, args.output, args.password)
            print(f"Encrypted successfully: {args.output}")
        else:
            decrypt_file(args.input, args.output, args.password)
            print(f"Decrypted and integrity verified: {args.output}")
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
