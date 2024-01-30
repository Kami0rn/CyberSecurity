from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import serialization

class ElectionSystem:
    def __init__(self):
        self.voters = []

    def generate_key_pair(self, student_id):
        # Set a static key size of 2048 bits
        key_size = 2048

        # Generate key pair
        private_key = asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Extract public key from the private key
        public_key = private_key.public_key()

        return private_key, public_key, student_id

    def serialize_public_and_private_keys(self, public_key, private_key, student_id):
        # Implement this method to serialize both public and private keys
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f"{student_id}_public_key.pem", 'wb') as f:
            f.write(pem_public)

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(f"{student_id}_private_key.pem", 'wb') as f:
            f.write(pem_private)

    def register_voter(self, student_id, public_key, private_key):
        self.voters.append({'student_id': student_id, 'public_key': public_key, 'private_key': private_key})
        self.serialize_public_and_private_keys(public_key, private_key, student_id)

def main():
    election_system = ElectionSystem()

    # Register voters and generate key pairs
    for i in range(10):
        print(f"\nRegistration for Voter {i + 1}:")
        student_id = f"ID{i + 1}"  # Manually set student_id for testing
        private_key, public_key, student_id = election_system.generate_key_pair(student_id)
        election_system.register_voter(student_id, public_key, private_key)

        # Print generated public key
        print(f"Public Key for Voter {i + 1}:\n{public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}")

    # Print registered student IDs and public keys
    print("\nRegistered student IDs and public keys:")
    for voter in election_system.voters:
        print(f"Student ID: {voter['student_id']}")
        print(f"Public Key:\n{voter['public_key'].public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}\n")

    print("Public and private keys saved to files.")

if __name__ == "__main__":
    main()
