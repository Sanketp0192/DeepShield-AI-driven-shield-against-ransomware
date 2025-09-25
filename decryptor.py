# decryptor.py

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PRIVATE_KEY_PATH = "private_key.pem"
OUTPUT_DIR = "decrypted_outputs"

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def decrypt_file(encrypted_data: bytes, filename: str, output_dir="decrypted_outputs") -> str:
    private_key = load_private_key()

    # Read length of RSA-encrypted AES key
    key_len = int.from_bytes(encrypted_data[:4], 'big')
    encrypted_key = encrypted_data[4:4 + key_len]
    iv = encrypted_data[4 + key_len:4 + key_len + 16]
    ciphertext = encrypted_data[4 + key_len + 16:]

    # Decrypt AES key using RSA private key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt file using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Save decrypted file to selected folder
    decrypted_path = os.path.join(output_dir, filename.replace(".enc", ""))

    with open(decrypted_path, "wb") as f:
        f.write(decrypted_data)

    return decrypted_path
