import traceback
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def decrypt_signature(public_key_path, signature_hex, hashed_data_hex):
    with open(public_key_path, "rb") as public_key_file:
        public_key_data = public_key_file.read()
        public_key = serialization.load_pem_public_key(
            public_key_data,
            backend=default_backend()
        )

    try:
        # Convert the hexadecimal string to bytes
        signature = bytes.fromhex(signature_hex)
        hashed_data = bytes.fromhex(hashed_data_hex)

        # Attempt to verify the signature and retrieve the digest
        public_key.verify(
            signature,
            hashed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        return hashed_data
    except Exception as e:
        print(f"Signature decryption failed: {e}\n{traceback.format_exc()}")
        return None

def main():
    public_key_path = input("Enter path to public key file: ")
    signature_hex = input("Enter the signature to decrypt (in hexadecimal format): ")
    hashed_data_hex = input("Enter the hashed data (in hexadecimal format): ")

    # Decrypt the signature back to the digest
    decrypted_digest = decrypt_signature(public_key_path, signature_hex, hashed_data_hex)

    # Print the decrypted digest
    if decrypted_digest:
        print(f"Decrypted Digest:\n{decrypted_digest.hex()}")

if __name__ == "__main__":
    main()
