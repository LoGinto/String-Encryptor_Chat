# decrypt_message.py
# Offline RSA Decryptor — decrypt message.enc using private_key.pem

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os

print("Offline Message Decryptor")
print("=" * 40)

# Check files exist
if not os.path.exists("message.enc"):
    print("Error: message.enc not found!")
    exit()
if not os.path.exists("private_key.pem"):
    print("Error: private_key.pem not found!")
    exit()

# Load private key
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Load encrypted file
with open("message.enc", "rb") as f:
    encrypted = f.read()

# Attempt decryption
try:
    decrypted_bytes = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    decrypted = decrypted_bytes.decode()
except Exception as e:
    print("Decryption failed! Wrong key? Corrupted file?")
    print("Error:", e)
    exit()

# Display
print("\nDECRYPTED MESSAGE:")
print("-" * 40)
print(decrypted)
print("-" * 40)
