from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization  # Add this import
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding


def verify_key_pair(private_key_path, public_key_path):
    with open(private_key_path, "rb") as private_key_file:
        private_key_data = private_key_file.read()
        private_key = serialization.load_pem_private_key(
            private_key_data,
            password=None,
            backend=default_backend()
        )

    with open(public_key_path, "rb") as public_key_file:
        public_key_data = public_key_file.read()
        public_key = serialization.load_pem_public_key(
            public_key_data,
            backend=default_backend()
        )

    try:
        # Attempt to perform a signing and verification operation
        message = b"Verification test message"
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )
        print("Key pair is valid.")
    except Exception as e:
        print(f"Key pair verification failed: {e}")

# Example usage
private_key_path = input("Enter path to private key file: ")
public_key_path = input("Enter path to public key file: ")

verify_key_pair(private_key_path, public_key_path)
