from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sha256(message):
    import hashlib
    return hashlib.sha256(message.encode()).hexdigest()

def caesar_cipher(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            shift_amount = shift % 26
            if char.islower():
                encrypted_char = chr((ord(char) - ord('a') + shift_amount) % 26 + ord('a'))
            else:
                encrypted_char = chr((ord(char) - ord('A') + shift_amount) % 26 + ord('A'))
            encrypted_message += encrypted_char
        else:
            encrypted_message += char
    return encrypted_message

def generate_rsa_keys():
    """Generate RSA public and private keys using OpenSSL cryptography."""
    
    
    # Generate a 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    return private_key, public_key

def sign_message(message, private_key):
    """Sign a message using the private key (RSA with SHA-256)."""

    
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """Verify a digital signature using the public key (RSA with SHA-256)."""

    
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def simulate_digital_signature(message, private_key):
    """Simulate and verify a digital signature using OpenSSL (RSA+SHA256)."""
    signature = sign_message(message, private_key)
    return signature

if __name__ == "__main__":
    # SHA-256 hashing demonstration
    print("--- SHA-256 Hashing ---")
    message = "Hello, World!"
    hash_value = sha256(message)
    print(f"SHA-256 hash of '{message}': {hash_value}")

    # Generate RSA key pair
    print("\n--- Digital Signature with OpenSSL (RSA+SHA256) ---")
    private_key, public_key = generate_rsa_keys()
    print("Generated RSA key pair (2048-bit)")
    
    # Sign the message
    signature = simulate_digital_signature(message, private_key)
    print(f"Signature created (first 64 bytes in hex): {signature[:32].hex()}...")
    
    # Verify the signature
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
    
    # Try to verify with a tampered message
    tampered_message = "Hello, World! (tampered)"
    is_valid_tampered = verify_signature(tampered_message, signature, public_key)
    print(f"Tampered message verification: {'VALID' if is_valid_tampered else 'INVALID'}")
    
    # Caesar cipher demonstration
    shift = 3
    encrypted_message = caesar_cipher(message, shift)
    print(f"\nCaesar cipher of '{message}' with shift {shift}: {encrypted_message}")