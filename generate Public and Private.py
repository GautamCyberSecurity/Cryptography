from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

# Generate RSA public and private keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Save the private key to a file
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save the public key to a file
    with open('public_key.pem', 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    return private_key, public_key

#encrypt a message with the private key

def encrypt_message_with_private_key(private_key, message):
    encrypted_message = private_key.sign(
        message.encode(),
        padding.PSS(
            mfg=padding .MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
        
        
    )
    return encrypted_message


def main():
    # Generate the keys
    private_key, public_key = generate_keys()
if __name__ == "__main__":
    main()