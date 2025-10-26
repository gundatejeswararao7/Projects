"""
Database Manager - Handles local encrypted storage of chat history
Only accessible by the user and admin
"""
import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64

class DatabaseManager:
    def __init__(self, username, admin_key='admin_master_key_2024'):
        self.username = username
        self.db_file = f"{username}_chat_history.db"
        self.admin_key = admin_key
        
        # Generate encryption key from username (user-specific)
        self.encryption_key = self.derive_key(username)
        self.cipher = Fernet(self.encryption_key)
        
        # Initialize database
        self.conn = sqlite3.connect(self.db_file)
        self.init_database()
    
    def derive_key(self, password):
        """Derive encryption key from password using PBKDF2"""
        salt = b'e2ee_chat_salt_2024'  # In production, use random salt per user
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return key
    
    def init_database(self):
        """Initialize database tables"""
        c = self.conn.cursor()
        
        # Messages table
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      sender TEXT,
                      recipient TEXT,
                      encrypted_content BLOB,
                      timestamp REAL,
                      message_type TEXT)''')
        
        # Contacts table
        c.execute('''CREATE TABLE IF NOT EXISTS contacts
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE,
                      public_key TEXT,
                      last_seen REAL)''')
        
        # Session info
        c.execute('''CREATE TABLE IF NOT EXISTS session_info
                     (key TEXT PRIMARY KEY,
                      value TEXT)''')
        
        self.conn.commit()
    
    def encrypt_content(self, content):
        """Encrypt content before storing"""
        return self.cipher.encrypt(content.encode('utf-8'))
    
    def decrypt_content(self, encrypted_content):
        """Decrypt content when retrieving"""
        return self.cipher.decrypt(encrypted_content).decode('utf-8')
    
    def store_message(self, sender, recipient, content, timestamp, msg_type):
        """Store encrypted message in local database"""
        encrypted_content = self.encrypt_content(content)
        
        c = self.conn.cursor()
        c.execute('INSERT INTO messages VALUES (NULL, ?, ?, ?, ?, ?)',
                  (sender, recipient, encrypted_content, timestamp, msg_type))
        self.conn.commit()
    
    def get_chat_history(self, with_user, limit=50):
        """Retrieve chat history with specific user"""
        c = self.conn.cursor()
        c.execute('''SELECT * FROM messages 
                     WHERE (sender = ? AND recipient = ?) 
                     OR (sender = ? AND recipient = ?)
                     ORDER BY timestamp DESC LIMIT ?''',
                  (self.username, with_user, with_user, self.username, limit))
        
        messages = c.fetchall()
        
        # Decrypt messages
        decrypted_messages = []
        for msg in reversed(messages):  # Reverse to show chronologically
            msg_id, sender, recipient, encrypted_content, timestamp, msg_type = msg
            decrypted_content = self.decrypt_content(encrypted_content)
            decrypted_messages.append((msg_id, sender, recipient, decrypted_content, timestamp, msg_type))
        
        return decrypted_messages
    
    def get_all_messages(self):
        """Retrieve all messages (for admin access)"""
        c = self.conn.cursor()
        c.execute('SELECT * FROM messages ORDER BY timestamp DESC')
        messages = c.fetchall()
        
        decrypted_messages = []
        for msg in messages:
            msg_id, sender, recipient, encrypted_content, timestamp, msg_type = msg
            decrypted_content = self.decrypt_content(encrypted_content)
            decrypted_messages.append((msg_id, sender, recipient, decrypted_content, timestamp, msg_type))
        
        return decrypted_messages
    
    def store_contact(self, username, public_key, last_seen):
        """Store contact information"""
        c = self.conn.cursor()
        c.execute('INSERT OR REPLACE INTO contacts VALUES (NULL, ?, ?, ?)',
                  (username, public_key, last_seen))
        self.conn.commit()
    
    def get_contacts(self):
        """Retrieve all contacts"""
        c = self.conn.cursor()
        c.execute('SELECT * FROM contacts ORDER BY last_seen DESC')
        return c.fetchall()
    
    def delete_chat_history(self, with_user):
        """Delete chat history with specific user"""
        c = self.conn.cursor()
        c.execute('''DELETE FROM messages 
                     WHERE (sender = ? AND recipient = ?) 
                     OR (sender = ? AND recipient = ?)''',
                  (self.username, with_user, with_user, self.username))
        self.conn.commit()
    
    def export_chat_history(self, output_file):
        """Export all chat history to file (admin function)"""
        messages = self.get_all_messages()
        
        with open(output_file, 'w') as f:
            f.write(f"Chat History Export for {self.username}\n")
            f.write("=" * 80 + "\n\n")
            
            for msg in messages:
                msg_id, sender, recipient, content, timestamp, msg_type = msg
                f.write(f"ID: {msg_id}\n")
                f.write(f"From: {sender}\n")
                f.write(f"To: {recipient}\n")
                f.write(f"Time: {timestamp}\n")
                f.write(f"Type: {msg_type}\n")
                f.write(f"Message: {content}\n")
                f.write("-" * 80 + "\n\n")
    
    def close(self):
        """Close database connection"""
        self.conn.close()
    
    @staticmethod
    def admin_decrypt_database(db_file, admin_key='admin_master_key_2024'):
        """
        Admin function to decrypt and read any user's database
        Only admin with correct key can access
        """
        if not os.path.exists(db_file):
            print(f"Database file {db_file} not found")
            return None
        
        # Extract username from filename
        username = db_file.replace('_chat_history.db', '')
        
        # Create temporary DB manager with admin key
        db = DatabaseManager(username, admin_key)
        messages = db.get_all_messages()
        db.close()
        
        return messages
