import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def decrypt_file(encrypted_data, private_key_path):
    # Extract the IV, encrypted symmetric key, and encrypted file data
    iv = encrypted_data[:16]
    encrypted_key = encrypted_data[16:272]
    encrypted_file_data = encrypted_data[272:]

    # Load the private key
    try:
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    except FileNotFoundError:
        print(f"Error: The file '{private_key_path}' was not found.")
        raise
    except PermissionError:
        print(f"Error: Permission denied when accessing '{private_key_path}'.")
        raise

    # Decrypt the symmetric key with the private key
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Decrypt the file data with the symmetric key
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

    return decrypted_data

def receive_file(save_path, private_key_path, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print('Server is listening...')
        conn, addr = s.accept()
        with conn:
            print(f'Connected by {addr}')
            encrypted_data = b''
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                encrypted_data += data

            decrypted_data = decrypt_file(encrypted_data, private_key_path)

            with open(save_path, 'wb') as f:
                f.write(decrypted_data)
            print('File received and decrypted successfully')

# Example usage
if __name__ == "__main__":
    receive_file('resume_received.docx', 'private_key.pem', '127.0.0.1', 59000)
