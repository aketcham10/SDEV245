# SHA-256 and Cryptographic Functions

A Python module demonstrating cryptographic hashing, encryption, and digital signatures.

## Features

### **SHA-256 Hashing**
- `sha256(message)` - Computes the SHA-256 hash of a message and returns the hexadecimal digest

### **Caesar Cipher**
- `caesar_cipher(message, shift)` - Simple substitution cipher that shifts each letter by a fixed amount
  - Preserves non-alphabetic characters
  - Handles both uppercase and lowercase letters

### **RSA Digital Signatures**
- `generate_rsa_keys()` - Generates a 2048-bit RSA public/private key pair
- `sign_message(message, private_key)` - Signs a message using the private key with RSA-PSS padding and SHA-256
- `verify_signature(message, signature, public_key)` - Verifies a digital signature; returns `True` if valid, `False` otherwise
- `simulate_digital_signature(message, private_key)` - Convenience wrapper that creates a digital signature

## Dependencies

- `cryptography` - OpenSSL-based cryptographic library for RSA and hashing operations
- `hashlib` - Python standard library for SHA-256 hashing

## Installation

```bash
pip install cryptography
```

## Usage

Run the script to see all cryptographic operations in action:

```bash
python sha-256.py
```

### Example Output

```
--- SHA-256 Hashing ---
SHA-256 hash of 'Hello, World!': dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f

--- Digital Signature with OpenSSL (RSA+SHA256) ---
Generated RSA key pair (2048-bit)
Signature created (first 64 bytes in hex): bb8c23633ee1dafa34fce6ad458ce84b2458c82fde1de3491dcaa24b3e4e95fb...
Signature verification: VALID
Tampered message verification: INVALID

Caesar cipher of 'Hello, World!' with shift 3: Khoor, Zruog!
```

## Security Notes

- **Caesar Cipher**: Educational use only - highly insecure for real-world applications
- **RSA Signatures**: Uses industry-standard 2048-bit RSA with PSS padding and SHA-256
- **Digital Signatures**: Demonstrates message authentication and tampering detection

## How It Works

1. **Hashing**: Converts any message into a fixed-length unique fingerprint (SHA-256)
2. **Digital Signatures**: 
   - Signs message using private key (only you can sign)
   - Verify signature using public key (anyone can verify authenticity)
   - Detects any tampering with the message
