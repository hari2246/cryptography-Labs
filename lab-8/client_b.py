import socket
import pickle
import random
import hashlib
from py_ecc.bls.ciphersuites import G2ProofOfPossession as ciphersuite
from py_ecc.optimized_bls12_381 import curve_order

def hash_message(message):
    return hashlib.sha256(message.encode()).digest()

# === Key generation ===
sk = random.randint(1, curve_order - 1)
pk = ciphersuite.SkToPk(sk)

# === Message ===
message = "Hello from Client B!"
signature = ciphersuite.Sign(sk, hash_message(message))

# === Send to Verifier Server ===
data = {
    'public_key': pk,
    'message': message,
    'signature': signature
}

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 5000))
client.send(pickle.dumps(data))

# === Receive result ===
result = client.recv(1024)
print("[Server Reply]: Signature Validity ->", result.decode())
client.close()
