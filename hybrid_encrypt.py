# hybrid_encrypt.py

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

def hybrid_encrypt(input_path, output_path, public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Generate AES key and IV
    aes_key = secrets.token_bytes(32)  
    iv = secrets.token_bytes(16)

    # Read and AES-encrypt file
    with open(input_path, "rb") as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # RSA encrypt AES key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Write to file: [len_encrypted_key][encrypted_key][iv][encrypted_data]
    with open(output_path, "wb") as f:
        f.write(len(encrypted_key).to_bytes(4, 'big'))
        f.write(encrypted_key)
        f.write(iv)
        f.write(encrypted_data)

    print(f"✅ File encrypted → {output_path}")

    try:
        os.remove(input_path)
        print(f"🗑️ Original file deleted → {input_path}")
    except Exception as e:
        print(f"⚠️ Could not delete original file: {e}")

# Example usage
hybrid_encrypt(
    input_path=r"D:\Users Sainath\Desktop\folder 1\Cybersecurity.pdf",
    output_path=r"D:\Users Sainath\Desktop\folder 1\Cybersecurity.pdf.enc",
    public_key_path="public_key.pem"
)
