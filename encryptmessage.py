# encrypt_message.py
# Offline RSA Encryptor — create encrypted message + keypair

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

print("Offline Message Encryptor")
print("=" * 40)

# If a keypair already exists, do NOT overwrite without warning
if os.path.exists("private_key.pem") or os.path.exists("public_key.pem"):
    print("Keys already exist! Delete them first if you want a new pair.")
    print("Existing files:")
    if os.path.exists("private_key.pem"): print(" - private_key.pem")
    if os.path.exists("public_key.pem"): print(" - public_key.pem")
    print("\nExiting for safety.")
    exit()

# Generate 2048-bit RSA key pair
print("Generating 2048-bit RSA key pair...")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Ask for message
message = input("\nEnter your secret message:\n> ")
if not message.strip():
    print("Empty message! Exiting.")
    exit()

# Encrypt message
encrypted = public_key.encrypt(
    message.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save encrypted message
with open("message.enc", "wb") as f:
    f.write(encrypted)
print("\nSaved encrypted file: message.enc")

# Save private key (PEM, no password for simplicity)
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open("private_key.pem", "wb") as f:
    f.write(private_bytes)
print("Saved private key: private_key.pem (DO NOT SHARE!)")

# Save public key (safe to share)
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("public_key.pem", "wb") as f:
    f.write(public_bytes)
print("Saved public key: public_key.pem (share this with others)")

print("\nDone!")
print("Send message.enc + your public_key.pem to your friend.")
print("They CANNOT decrypt without your private key.")
