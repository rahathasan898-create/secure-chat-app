import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class CryptoUtils:
    @staticmethod
    def generate_rsa_key_pair():
        """Generates a new RSA private and public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(public_key):
        """Serializes a public key to PEM format."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def deserialize_public_key(pem_data):
        """Deserializes a public key from PEM format."""
        return serialization.load_pem_public_key(pem_data)

    @staticmethod
    def encrypt_rsa(public_key, data):
        """Encrypts data (like an AES key) using an RSA public key."""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def decrypt_rsa(private_key, encrypted_data):
        """Decrypts data using an RSA private key."""
        return private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def generate_aes_key():
        """Generates a random 32-byte (256-bit) AES key."""
        return os.urandom(32)

    @staticmethod
    def encrypt_aes(key, plaintext: bytes):
        """Encrypts a plaintext message using AES-CFB."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def decrypt_aes(key, encrypted_data: bytes):
        """Decrypts a ciphertext message using AES-CFB."""
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    @staticmethod
    def generate_dh_parameters():
        """Generates Diffie-Hellman parameters (for Forward Secrecy)."""
        return dh.generate_parameters(generator=2, key_size=2048)

    @staticmethod
    def generate_dh_key_pair(parameters):
        """Generates a DH private and public key pair."""
        private_key = parameters.generate_private_key()
        return private_key, private_key.public_key()

    @staticmethod
    def derive_dh_shared_key(private_key, peer_public_key):
        """Derives a shared AES key from DH exchange."""
        shared_key = private_key.exchange(peer_public_key)
        # Use HKDF to derive a 32-byte AES key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'forward-secrecy-handshake',
        ).derive(shared_key)
        return derived_key
