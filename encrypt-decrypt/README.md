# Encrypt-Decrypt Utility

A simple Python utility for encrypting and decrypting strings using JWT (JSON Web Tokens) with HMAC-SHA256.

## Functions

### `encrypt(plain_text, key)`
- **Parameters**: `plain_text` (str) - The text to encrypt, `key` (str) - The secret key for encryption
- **Returns**: A JWT token containing the encrypted data

### `decrypt(encrypted_text, key)`
- **Parameters**: `encrypted_text` (str) - The JWT token to decrypt, `key` (str) - The same secret key used for encryption
- **Returns**: The original plain text string

## Usage Example

```python
from encrypt import encrypt, decrypt

key = 'my_super_secret_key_extra_super_secure_awesome_key'
plain_text = "Hello, World!"

# Encrypt the text
encrypted_text = encrypt(plain_text, key)
print("Encrypted text:", encrypted_text)

# Decrypt the text
decrypted_text = decrypt(encrypted_text, key)
print("Decrypted text:", decrypted_text)
```

## Requirements

- Python 3.x
- PyJWT library (`pip install PyJWT`)

## Running the Script

```bash
python encrypt.py
```

This will run the example and print the encrypted and decrypted text.