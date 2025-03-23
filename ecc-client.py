import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    client_private_key = ec.generate_private_key(ec.SECP256R1())
    client_public_key = client_private_key.public_key()

    server_public_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_bytes)

    client_public_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.sendall(client_public_bytes)
    
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    print("Client derived shared secret:", shared_secret.hex())
    
    client_socket.close()

client()