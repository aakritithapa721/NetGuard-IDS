import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()  # load variables from .env

KEY_PATH = os.getenv("ENCRYPTION_KEY")

# Generate key (run once)
def generate_key():
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

# Load key
def load_key():
    if not os.path.exists(KEY_PATH):
        return generate_key()
    return open(KEY_PATH, "rb").read()

# Encrypt message
def encrypt_message(message):
    key = load_key()
    f = Fernet(key)
    return f.encrypt(message.encode())

# Decrypt message
def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    return f.decrypt(encrypted_message).decode()