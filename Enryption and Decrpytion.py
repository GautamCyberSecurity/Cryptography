from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(plain_text, key):
    # can chose the key is exactly 16, 24, or 32 bytes long
    key = key.ljust(32)[:32].encode()  # AES-256 (32 bytes)
    
    # Generate a random Initialization Vector (IV)
    iv = get_random_bytes(16)
    
    # Create AES cipher in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the plaintext
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    
    return base64.b64encode(iv + encrypted_bytes).decode()

def aes_decrypt(encrypted_data, key):
    # Can chose the key is exactly 16, 24, or 32 bytes long
    key = key.ljust(32)[:32].encode()  # AES-256 (32 bytes)
    
    # Decode the base64-encoded input
    encrypted_data = base64.b64decode(encrypted_data)
    
    # Extract the IV from the first 16 bytes
    iv = encrypted_data[:16]
    
    # Extract the encrypted content
    encrypted_bytes = encrypted_data[16:]
    
    # Create AES cipher with the same IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    
    decrypted_text = unpad(cipher.decrypt(encrypted_bytes), AES.block_size).decode()
    
    return decrypted_text

# User Input
plain_text = input("Enter the message to encrypt: ")
key = input("Enter a secret key (16, 24, or 32 characters recommended): ")

# Encrypt
encrypted_data = aes_encrypt(plain_text, key)
print("\nEncrypted Data:", encrypted_data)

# Decrypt
decrypted_text = aes_decrypt(encrypted_data, key)
print("Decrypted Text:", decrypted_text)
