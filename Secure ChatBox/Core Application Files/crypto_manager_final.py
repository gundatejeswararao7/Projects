"""
Cryptography Manager - Handles RSA and AES encryption
Implements hybrid encryption: RSA for key exchange, AES for message encryption
Complete implementation with all security features
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

class CryptoManager:
    def __init__(self, username):
        self.username = username
        self.private_key = None
        self.public_key = None
        self.key_file = f"{username}_private_key.pem"
        
        # Generate or load RSA keys
        self.load_or_generate_keys()
    
    def generate_rsa_keys(self):
        """Generate RSA key pair (2048-bit for security)"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def save_private_key(self):
        """Save private key to encrypted file"""
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(self.key_file, 'wb') as f:
            f.write(pem)
    
    def load_private_key(self):
        """Load private key from file"""
        try:
            with open(self.key_file, 'rb') as f:
                pem = f.read()
            self.private_key = serialization.load_pem_private_key(
                pem,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            return True
        except FileNotFoundError:
            return False
    
    def load_or_generate_keys(self):
        """Load existing keys or generate new ones"""
        if not self.load_private_key():
            print("🔑 Generating new RSA key pair...")
            self.generate_rsa_keys()
            self.save_private_key()
            print("✅ Keys generated and saved")
        else:
            print("🔑 Loaded existing RSA keys")
    
    def export_public_key(self):
        """Export public key as PEM string"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def import_public_key(self, pem_string):
        """Import public key from PEM string"""
        pem = pem_string.encode('utf-8')
        return serialization.load_pem_public_key(pem, backend=default_backend())
    
    def generate_aes_key(self):
        """Generate random AES-256 key"""
        return os.urandom(32)  # 256 bits
    
    def generate_iv(self):
        """Generate random initialization vector for AES"""
        return os.urandom(16)  # 128 bits
    
    def encrypt_message(self, message, recipient_public_key_pem):
        """
        Encrypt message using hybrid encryption:
        1. Generate random AES key
        2. Encrypt message with AES
        3. Encrypt AES key with recipient's RSA public key
        4. Return combined encrypted data
        """
        # Generate AES key and IV
        aes_key = self.generate_aes_key()
        iv = self.generate_iv()
        
        # Encrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message to block size (16 bytes for AES)
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        recipient_public_key = self.import_public_key(recipient_public_key_pem)
        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Combine everything into a JSON structure
        encrypted_data = {
            'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(encrypted_message).decode('utf-8')
        }
        
        return json.dumps(encrypted_data)
    
    def decrypt_message(self, encrypted_data_json):
        """
        Decrypt message using hybrid encryption:
        1. Decrypt AES key using own RSA private key
        2. Use AES key to decrypt message
        3. Return plaintext message
        """
        # Parse encrypted data
        encrypted_data = json.loads(encrypted_data_json)
        encrypted_aes_key = base64.b64decode(encrypted_data['encrypted_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        # Decrypt AES key with RSA
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_message[-1]
        message_bytes = padded_message[:-padding_length]
        
        return message_bytes.decode('utf-8')
    
    def sign_message(self, message):
        """Create digital signature for message authentication"""
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature_b64, sender_public_key_pem):
        """Verify digital signature"""
        try:
            sender_public_key = self.import_public_key(sender_public_key_pem)
            signature = base64.b64decode(signature_b64)
            
            sender_public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
