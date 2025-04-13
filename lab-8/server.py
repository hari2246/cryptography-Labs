import socket
import threading
import pickle
import hashlib
from py_ecc.bls.ciphersuites import G2ProofOfPossession as ciphersuite

def hash_message(message):
    return hashlib.sha256(message.encode()).digest()

def handle_client(client_socket, address):
    print(f"[+] Connection from {address}")

    try:
        data = client_socket.recv(4096)
        received = pickle.loads(data)

        public_key = received['public_key']
        message = received['message']
        signature = received['signature']

        is_valid = ciphersuite.Verify(public_key, hash_message(message), signature)
        print(f"[{address}] Message: '{message}' | Signature Valid: {is_valid}")

        client_socket.send(str(is_valid).encode())
    except Exception as e:
        print(f"[!] Error handling client {address}: {e}")
        client_socket.send(str(False).encode())
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 5000))
    server.listen(5)
    print("[*] Verifier Server running on port 5000...")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
