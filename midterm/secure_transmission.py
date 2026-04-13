import argparse
import base64
import hashlib
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def read_input_data(message: str | None, file_path: str | None) -> bytes:
    if file_path:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Input file not found: {file_path}")
        return path.read_bytes()
    if message is not None:
        return message.encode("utf-8")
    raise ValueError("No input provided. Use --message or --file.")


def sha256_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(password: str, salt: bytes | None = None) -> Tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf_inst = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf_inst.derive(password.encode("utf-8")), salt


def encrypt_data(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce=nonce, data=plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce=nonce, data=ciphertext, associated_data=None)


def format_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Secure Transmission: hash, encrypt, decrypt, verify.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--message", help="Message text to secure.")
    group.add_argument("--file", help="Path to an input file to secure.")
    parser.add_argument("--password", help="Password for symmetric encryption. If omitted, prompts securely.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        plaintext = read_input_data(args.message, args.file)
    except Exception as exc:
        print(f"Error reading input: {exc}")
        return 1

    original_hash = sha256_hash(plaintext)
    print(f"SHA-256 hash of input: {original_hash}")

    password = args.password
    if password is None:
        try:
            import getpass
            password = getpass.getpass("Enter encryption password: ")
        except Exception:
            password = input("Enter encryption password: ")

    if not password:
        print("A non-empty password is required.")
        return 1

    key, salt = derive_key(password)
    nonce, ciphertext = encrypt_data(plaintext, key)

    print("\nEncrypted payload:")
    print(f"salt: {format_bytes(salt)}")
    print(f"nonce: {format_bytes(nonce)}")
    print(f"ciphertext: {format_bytes(ciphertext)}")

    try:
        decrypted = decrypt_data(ciphertext, nonce, key)
    except Exception as exc:
        print(f"Decryption failed: {exc}")
        return 1

    decrypted_hash = sha256_hash(decrypted)
    print(f"\nSHA-256 hash after decryption: {decrypted_hash}")

    if decrypted == plaintext and decrypted_hash == original_hash:
        print("Integrity verification succeeded: decrypted data matches original input.")
        return 0

    print("Integrity verification failed: decrypted data does not match original input.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
