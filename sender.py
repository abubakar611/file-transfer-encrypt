import socket
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_keys(private_key_path, public_key_path):
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("Generating RSA keys...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize private key to PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(pem)

        # Serialize public key to PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(pem)
        print("RSA keys generated and saved.")

def encrypt_file(file_path, public_key_path):
    # Read the file data
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate a random symmetric key
    symmetric_key = os.urandom(32)
    iv = os.urandom(16)  # Initialization vector

    # Encrypt the file data with the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    # Load the public key
    try:
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        print(f"Error: The file '{public_key_path}' was not found.")
        raise
    except PermissionError:
        print(f"Error: Permission denied when accessing '{public_key_path}'.")
        raise

    # Encrypt the symmetric key with the public key
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return iv + encrypted_key + encrypted_data  # Include IV at the beginning

def send_file(file_path, public_key_path, host, port):
    generate_keys('private_key.pem', public_key_path)  # Ensure keys are available
    encrypted_data = encrypt_file(file_path, public_key_path)
    
    # Create a socket connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(encrypted_data)
        print('File sent successfully')

# Example usage
if __name__ == "__main__":
    send_file('resume.docx', 'public_key.pem', '127.0.0.1', 59000)
