from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

AES_KEY = b"ThisIsASecretKey12345678" 
IV = b"InitializationVe" 

def encrypt_file(input_file, output_file):
    with open(input_file, "rb") as f:
        plaintext = f.read()
    
    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))
    enc_text=base64.b64encode(encrypted_data)
    print(enc_text)

    with open(output_file, "wb") as f:
        f.write(enc_text)
    
    print(f"File '{input_file}' encrypted successfully as '{output_file}'")

def decrypt_file(input_file, output_file):
    with open(input_file, "rb") as f:
        encrypted_data = base64.b64decode(f.read())

    cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    print(decrypted_data)

    with open(output_file, "wb") as f:
        f.write(decrypted_data)
    
    print(f"File '{input_file}' decrypted successfully as '{output_file}'")

encrypt_file("test.txt", "encrypted.aes")
decrypt_file("encrypted.aes", "decrypted.txt")
