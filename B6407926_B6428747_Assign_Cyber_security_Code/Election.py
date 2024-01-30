import traceback
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def hash_and_sign(student_id, candidate, private_key):
    # Combine student ID and candidate and hash the result
    data_to_hash = f"{student_id}:{candidate}".encode('utf-8')
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(data_to_hash)
    hashed_data = digest.finalize()

    # Sign the hashed data with the private key
    signature = private_key.sign(
        hashed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )

    return hashed_data, signature, student_id, candidate

def main():
    votes_data = []  # List to store vote information

    for i in range(1, 11):
        private_key_path = f"C:\\Users\\user\\Desktop\\CPE\\2-2566\\CS\\Assign1\\PrivateWallet\\ID{i}_private_key.pem"
        with open(private_key_path, "rb") as private_key_file:
            private_key_data = private_key_file.read()
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None,
                backend=default_backend()
            )

        # Input for student ID and election candidate
        student_id = input(f"Enter student ID for Voter {i} (e.g., B64079{i}): ")
        candidate = input(f"Enter the election candidate [A, B, C] for {student_id}: ")

        # Hash and sign the data
        hashed_data, signature, student_id, candidate = hash_and_sign(student_id, candidate, private_key)

        # Print the digest and signature
        print(f"Digest of {student_id} and candidate {candidate}:\n{hashed_data.hex()}")
        print(f"Signature for {student_id} and candidate {candidate}:\n{signature.hex()}")

        # Store the information in the list
        votes_data.append((student_id, candidate, signature))

    # Display the table
    print("\nVote Table:")
    print("StudentID\tSelectedCandidate\tSignature")
    for student_id, candidate, signature in votes_data:
        print(f"{student_id}\t\t{candidate}\t\t\t{signature.hex()}")

    # Calculate the ChainOfResult
    chain_of_result = hashes.Hash(hashes.SHA512(), backend=default_backend())
    for _, _, signature in votes_data:
        chain_of_result.update(signature)
    chain_result = chain_of_result.finalize()

    print("\nChainOfResult:")
    print(chain_result.hex())

if __name__ == "__main__":
    main()
