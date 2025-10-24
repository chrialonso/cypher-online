import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(master_password, salt):
    """
    Derive a 32-byte encryption key from the master password and salt.
    """

    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(master_password.encode())

def generate_salt():
    """
    Generate a 16-byte random salt for key derivation.
    """
    return os.urandom(16)

def encrypt_password(password, key):
    """
    Encrypt the given password with AES-GCM using the provided key.
    Returns raw bytes containing IV + tag + ciphertext.
    """
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    return urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode()

def decrypt_password(encrypted_password, key):
    """
    Decrypt URL-safe base64 string containing IV + tag + ciphertext with AES-GCM.
    Returns the plaintext password.
    """
    if isinstance(encrypted_password, bytes):
        encrypted_password = encrypted_password.decode()

    encrypted_password += "=" * ((4 - len(encrypted_password) % 4) % 4)
    
    encrypted_data = urlsafe_b64decode(encrypted_password.encode())
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return(decryptor.update(ciphertext) + decryptor.finalize()).decode()

def hash_master_password(master_password):
    """
    Hash the master password using bcrypt
    """
    return bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

def check_master_password(password, hashed_password):
    """
    Verify a plaintext password against a bcrypt hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
