from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

AES_KEY = b"ThisIsASecretKey12345678"  
IV = b"InitializationVe"  

def encrypt_file(input_file, output_file):
    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()
        
        cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
        encrypted_data = cipher.encrypt(pad(plaintext, AES.block_size))
        
        with open(output_file, "wb") as f:
            f.write(base64.b64encode(encrypted_data))
        
        print(f"✅ File '{input_file}' encrypted successfully as '{output_file}'")
    except FileNotFoundError:
        print(f"❌ Error: File '{input_file}' not found.")

def decrypt_file(input_file, output_file):
    try:
        with open(input_file, "rb") as f:
            encrypted_data = base64.b64decode(f.read())

        cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        
        print(f"✅ File '{input_file}' decrypted successfully as '{output_file}'")
    except FileNotFoundError:
        print(f"❌ Error: File '{input_file}' not found.")
    except ValueError:
        print("❌ Error: Decryption failed! Possibly incorrect key or corrupted file.")

if __name__ == "__main__":
    print("🔒 AES File Encryption & Decryption")
    
    while True:
        print("\n1 Encrypt a file\n2️ Decrypt a file\n3️ Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            file_name = input("Enter the file name to encrypt: ").strip()
            encrypted_name = file_name + ".aes"
            encrypt_file(file_name, encrypted_name)
        
        elif choice == "2":
            file_name = input("Enter the encrypted file name to decrypt: ").strip()
            decrypted_name = "decrypted_" + os.path.splitext(file_name)[0] + ".txt"
            decrypt_file(file_name, decrypted_name)
        
        elif choice == "3":
            print("🔐 Exiting... Stay Secure! 🔒")
            break
        else:
            print("❌ Invalid choice! Please enter 1, 2, or 3.")
