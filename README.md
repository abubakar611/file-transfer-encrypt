# Encrypted File Transfer

This project demonstrates how to securely transfer files over a network using encryption with sockets. It includes both a sender and receiver script where files are encrypted before transmission and decrypted after reception.

## Features

- **File Encryption:** Uses AES encryption with a symmetric key to encrypt the file data.
- **Public Key Encryption:** Encrypts the symmetric key with RSA public key encryption.
- **File Transfer:** Transfers the encrypted file data over a network socket.
- **Decryption:** Decrypts the received file data using RSA private key and AES symmetric key.

## Components

### `sender.py`

This script handles the following tasks:
1. **Encrypt File Data:** Encrypts the file using AES with a symmetric key. The symmetric key itself is encrypted using RSA public key encryption.
2. **Send File Data:** Connects to the receiver and sends the encrypted file data along with metadata (file name and size).

#### Example Usage
```bash
python sender.py
```

### `receiver.py`

This script performs the following:
1. **Receive File Data:** Receives encrypted file data from the sender.
2. **Decrypt File Data:** Decrypts the symmetric key using RSA private key and then uses it to decrypt the file data.
3. **Save File:** Writes the decrypted file data to a local file.

#### Example Usage
```bash
python receiver.py
```

## Prerequisites

- Python 3.x
- `cryptography` library (install via `pip install cryptography`)

## Setup

1. **Generate RSA Key Pair:** Create a public and private key pair using OpenSSL or similar tools. Save them as `public_key.pem` and `private_key.pem` respectively.

2. **Save the RSA Keys:**
   - **Public Key (`public_key.pem`):** Used by the sender to encrypt the symmetric key.
   - **Private Key (`private_key.pem`):** Used by the receiver to decrypt the symmetric key.

3. **Prepare the Files:**
   - Place the file to be transferred (e.g., `resume.docx`) in the same directory as `sender.py`.
   - Ensure `public_key.pem` is accessible by `sender.py`.

4. **Run the Scripts:**
   - Start the receiver script to listen for incoming connections.
   - Run the sender script to send the file.

## Troubleshooting

- **File Not Found Errors:** Ensure that `public_key.pem` and `private_key.pem` are located in the correct directory.
- **Permission Denied Errors:** Check file permissions and ensure that the script has access to the files it needs to open.
