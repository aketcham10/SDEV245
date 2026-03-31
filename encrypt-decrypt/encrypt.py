import jwt
def encrypt(plain_text, key):
    # Create a JWK key
    token = jwt.encode({'data': plain_text}, key.encode('utf-8'), algorithm='HS256')
    return token

def decrypt(encrypted_text, key):
    # Create a JWK key
    token = jwt.decode(encrypted_text, key.encode('utf-8'), algorithms=['HS256'])
    return token['data']


if __name__ == "__main__":
    key = 'my_super_secret_key_extra_super_secure_awesome_key'
    plain_text = "Hello, World!"
    encrypted_text = encrypt(plain_text, key)
    decrypted_text = decrypt(encrypted_text, key)
    print("Encrypted text:", encrypted_text)
    print("Decrypted text:", decrypted_text)