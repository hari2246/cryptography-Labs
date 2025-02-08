import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

AES_KEY = b"ThisIsASecretKey12345678"
IV = b"InitializationVe"

def encrypt_text(plain_text):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    encrypted_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return base64.b64encode(encrypted_bytes)

def decrypt_text(encrypted_text):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_text)), AES.block_size)
    return decrypted_bytes.decode()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 12351))

message = "Hello, Server!"
encrypted_message = encrypt_text(message)
client.send(encrypted_message)

msg = client.recv(1024)
decrypted_message = decrypt_text(msg)
print(f"Decrypted message: {decrypted_message}")

client.close()
