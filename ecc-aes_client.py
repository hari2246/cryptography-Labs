import socket
import time  # Import time module
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def decrypt_message(shared_secret, ciphertext):
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    iv, actual_ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    return decrypted_padded_message.decode().strip()

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))
print("Connected to server.")

# Measure key generation time
start_time = time.time()
client_private_key = ec.generate_private_key(ec.SECP521R1())  # Change to SECP384R1 or SECP521R1
end_time = time.time()
print(f"Client Key Generation Time: {end_time - start_time:.6f} seconds")

client_public_key = client_private_key.public_key()
client_public_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client_socket.sendall(client_public_bytes)

server_public_bytes = client_socket.recv(1024)
server_public_key = serialization.load_pem_public_key(server_public_bytes)

# Measure shared secret derivation time
start_time = time.time()
shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
end_time = time.time()
print(f"Shared Secret Derivation Time: {end_time - start_time:.6f} seconds")

ciphertext = client_socket.recv(1024)

# Measure decryption time
start_time = time.time()
decrypted_message = decrypt_message(shared_secret, ciphertext)
end_time = time.time()
print(f"Decryption Time: {end_time - start_time:.6f} seconds")

print("Decrypted Message:", decrypted_message)
client_socket.close()
