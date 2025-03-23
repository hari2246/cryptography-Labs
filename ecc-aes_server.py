import os
import socket
import time  # Import time module
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_message(shared_secret, message):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = message + ' ' * (16 - len(message) % 16)
    ciphertext = encryptor.update(padded_message.encode()) + encryptor.finalize()
    return iv + ciphertext

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server is listening...")

conn, addr = server_socket.accept()
print("Connection established with", addr)

# Measure key generation time
start_time = time.time()
server_private_key = ec.generate_private_key(ec.SECP521R1())  # Change to SECP384R1 or SECP521R1
end_time = time.time()
print(f"Server Key Generation Time: {end_time - start_time:.6f} seconds")

server_public_key = server_private_key.public_key()
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
conn.sendall(server_public_bytes)

client_public_bytes = conn.recv(1024)
client_public_key = serialization.load_pem_public_key(client_public_bytes)

# Measure shared secret derivation time
start_time = time.time()
shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
end_time = time.time()
print(f"Shared Secret Derivation Time: {end_time - start_time:.6f} seconds")

message = "Hell0 SRM AP"

# Measure encryption time
start_time = time.time()
ciphertext = encrypt_message(shared_secret, message)
end_time = time.time()
print(f"Encryption Time: {end_time - start_time:.6f} seconds")

# Measure ciphertext size
print(f"Ciphertext Size: {len(ciphertext)} bytes")

conn.sendall(ciphertext)
print("Encrypted message sent.")
conn.close()
server_socket.close()
