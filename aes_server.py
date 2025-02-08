import socket
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad,pad

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

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 12353))
server.listen(1)

print("Server is listening for connections...")
conn, addr = server.accept()
print(f"Connection received from {addr}")
while True:
    data_before=conn.recv(1024)
    print("Before decrytion: ",data_before)
    
    data = decrypt_text(data_before)
    if data.lower() == "quit":
        print("Connection closed.")
        break
    
    msg1=input("Enter message : ")
    conn.send((encrypt_text(msg1)))


conn.close()
server.close()
