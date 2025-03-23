import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Server listening on port 12345...")
    
    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")
    
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()

    server_public_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    conn.sendall(server_public_bytes)

    client_public_bytes = conn.recv(1024)
    client_public_key = serialization.load_pem_public_key(client_public_bytes)

    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    print("Server derived shared secret:", shared_secret.hex())
    
    conn.close()
    server_socket.close()

server()