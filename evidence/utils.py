import os
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')

def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_private_key(pem_str):
    private_key = serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    return private_key

def load_public_key(pem_str):
    public_key = serialization.load_pem_public_key(
        pem_str.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_file(input_path, output_path, key):
    fernet = Fernet(key)
    with open(input_path, 'rb') as f_in:
        data = f_in.read()
    encrypted = fernet.encrypt(data)
    with open(output_path, 'wb') as f_out:
        f_out.write(encrypted)

def decrypt_file(input_path, output_path, key):
    fernet = Fernet(key)
    with open(input_path, 'rb') as f_in:
        encrypted_data = f_in.read()
    decrypted = fernet.decrypt(encrypted_data)
    with open(output_path, 'wb') as f_out:
        f_out.write(decrypted)

def compute_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def wrap_key(symmetric_key, public_key):
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def unwrap_key(wrapped_key, private_key):
    symmetric_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return symmetric_key

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_text(text, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_text = text.encode() + b'\0' * (16 - len(text.encode()) % 16)
    encrypted = encryptor.update(padded_text) + encryptor.finalize()
    return salt + iv + encrypted

def decrypt_text(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted = encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    return decrypted_padded.rstrip(b'\0').decode()