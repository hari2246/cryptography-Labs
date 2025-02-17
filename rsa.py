#RSA Implementation
#Write a program to implement RSA algorithm for key-Generation
import math

p=int(input("Enter a prime number 1:"))
q=int(input("Enter a prime number 2:"))

n=p*q
phi = (p-1)*(q-1)
for i in range(2,phi):
    if(math.gcd(phi,i)==1):
        e=i
        break
print("Public Key:",e,n)
d=pow(e,-1,phi)
print("Private Key:",d)

#2.Use solution of question 1 to implement encryption and decryption process to encrypt a number and an alphabet

def encrypt(text,e,n):
    cipher = pow(text,e,n)
    print(text," cipher in RSA:",cipher)
    return cipher

def decrypt(cipher,d,n):
    text = pow(cipher,d,n)
    print(cipher," decrypted text:",chr(text))
    return text

text = ord(input("Enter a charcter:"))
cipher = encrypt(text,e,n)
text = decrypt(cipher,d,n)