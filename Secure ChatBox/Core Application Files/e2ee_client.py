"""
E2EE Chat Client - Command-line interface with encryption
Complete implementation with all features
"""
import socketio
import threading
import time
import getpass
import os
import sys
from datetime import datetime
from crypto_manager import CryptoManager
from db_manager import DatabaseManager

class ChatClient:
    def __init__(self, server_url='http://localhost:5000'):
        self.sio = socketio.Client()
        self.server_url = server_url
        self.username = None
        self.crypto = None
        self.db = None
        self.online_users = []
        self.active_chats = {}
        self.running = True
        
        # Setup event handlers
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup SocketIO event handlers"""
        
        @self.sio.on('connect')
        def on_connect():
            print("✅ Connected to server")
        
        @self.sio.on('disconnect')
        def on_disconnect():
            print("❌ Disconnected from server")
        
        @self.sio.on('register_response')
        def on_register(data):
            if data['success']:
                print(f"✅ {data['message']}")
                self.online_users = data.get('online_users', [])
                if self.username in self.online_users:
                    self.online_users.remove(self.username)
                print(f"\n📱 Online users: {', '.join(self.online_users) if self.online_users else 'None'}")
            else:
                print(f"❌ {data['message']}")
                self.running = False
        
        @self.sio.on('user_online')
        def on_user_online(data):
            username = data['username']
            if username != self.username and username not in self.online_users:
                self.online_users.append(username)
                print(f"\n🟢 {username} is now online")
                self.show_prompt()
        
        @self.sio.on('user_offline')
        def on_user_offline(data):
            username = data['username']
            if username in self.online_users:
                self.online_users.remove(username)
                print(f"\n🔴 {username} went offline")
                self.show_prompt()
        
        @self.sio.on('public_key_response')
        def on_public_key(data):
            if data['success']:
                username = data['username']
                public_key = data['public_key']
                # Store public key for this user
                if username not in self.active_chats:
                    self.active_chats[username] = {}
                self.active_chats[username]['public_key'] = public_key
        
        @self.sio.on('receive_message')
        def on_receive_message(data):
            sender = data['sender']
            encrypted_msg = data['encrypted_message']
            timestamp = data['timestamp']
            
            # Decrypt message
            try:
                decrypted = self.crypto.decrypt_message(encrypted_msg)
                
                # Store in local database
                self.db.store_message(sender, self.username, decrypted, timestamp, 'received')
                
                # Display message
                time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
                print(f"\n💬 [{time_str}] {sender}: {decrypted}")
                self.show_prompt()
            except Exception as e:
                print(f"\n❌ Failed to decrypt message from {sender}: {e}")
                self.show_prompt()
        
        @self.sio.on('online_users_list')
        def on_users_list(data):
            self.online_users = [u for u in data['users'] if u != self.username]
    
    def show_prompt(self):
        """Display command prompt"""
        print(f"\n{self.username}> ", end='', flush=True)
    
    def connect(self):
        """Connect to server"""
        try:
            self.sio.connect(self.server_url)
            return True
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def register(self, username):
        """Register user with server"""
        self.username = username
        
        # Initialize crypto and database
        self.crypto = CryptoManager(username)
        self.db = DatabaseManager(username)
        
        # Send registration with public key
        public_key_pem = self.crypto.export_public_key()
        self.sio.emit('register', {
            'username': username,
            'public_key': public_key_pem
        })
        
        time.sleep(1)  # Wait for response
    
    def request_public_key(self, target_user):
        """Request public key for target user"""
        self.sio.emit('request_public_key', {
            'target_user': target_user,
            'requester': self.username
        })
        time.sleep(0.5)  # Wait for key
    
    def send_message(self, recipient, message):
        """Encrypt and send message"""
        if recipient not in self.online_users:
            print(f"❌ User {recipient} is not online")
            return
        
        # Get recipient's public key if not cached
        if recipient not in self.active_chats or 'public_key' not in self.active_chats[recipient]:
            self.request_public_key(recipient)
            time.sleep(0.5)
        
        if recipient not in self.active_chats or 'public_key' not in self.active_chats[recipient]:
            print(f"❌ Could not get public key for {recipient}")
            return
        
        try:
            # Encrypt message using recipient's public key
            recipient_public_key = self.active_chats[recipient]['public_key']
            encrypted = self.crypto.encrypt_message(message, recipient_public_key)
            
            # Send encrypted message
            self.sio.emit('send_message', {
                'sender': self.username,
                'recipient': recipient,
                'encrypted_message': encrypted
            })
            
            # Store in local database
            timestamp = time.time()
            self.db.store_message(self.username, recipient, message, timestamp, 'sent')
            
            time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            print(f"✅ [{time_str}] Message sent to {recipient}")
        except Exception as e:
            print(f"❌ Failed to send message: {e}")
    
    def show_chat_history(self, with_user):
        """Display chat history with specific user"""
        messages = self.db.get_chat_history(with_user)
        
        if not messages:
            print(f"📭 No chat history with {with_user}")
            return
        
        print(f"\n{'='*60}")
        print(f"💬 Chat History with {with_user}")
        print(f"{'='*60}")
        
        for msg in messages:
            _, sender, recipient, content, timestamp, msg_type = msg
            time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            if msg_type == 'sent':
                print(f"[{time_str}] You → {recipient}: {content}")
            else:
                print(f"[{time_str}] {sender} → You: {content}")
        
        print(f"{'='*60}")
    
    def list_online_users(self):
        """Display online users"""
        if not self.online_users:
            print("📭 No other users online")
        else:
            print("\n📱 Online Users:")
            for user in self.online_users:
                print(f"  🟢 {user}")
    
    def show_help(self):
        """Display help menu"""
        print("\n" + "="*60)
        print("🔒 E2EE Chat Application - Commands")
        print("="*60)
        print("/msg <user> <message>  - Send encrypted message")
        print("/history <user>        - View chat history")
        print("/users                 - List online users")
        print("/help                  - Show this help menu")
        print("/quit                  - Exit application")
        print("="*60)
    
    def run(self):
        """Main client loop"""
        print("\n" + "="*60)
        print("🔒 Welcome to E2EE Chat Application")
        print("="*60)
        
        username = input("Enter username: ").strip()
        
        if not username:
            print("❌ Username cannot be empty")
            return
        
        print("\n🔄 Connecting to server...")
        if not self.connect():
            return
        
        print("🔑 Generating encryption keys...")
        self.register(username)
        
        if not self.running:
            return
        
        print("\n✅ Ready to chat! Type /help for commands")
        self.show_prompt()
        
        try:
            while self.running:
                try:
                    command = input().strip()
                    
                    if not command:
                        self.show_prompt()
                        continue
                    
                    if command == '/quit':
                        print("\n👋 Goodbye!")
                        break
                    
                    elif command == '/help':
                        self.show_help()
                    
                    elif command == '/users':
                        self.list_online_users()
                    
                    elif command.startswith('/msg '):
                        parts = command.split(' ', 2)
                        if len(parts) < 3:
                            print("❌ Usage: /msg <user> <message>")
                        else:
                            recipient = parts[1]
                            message = parts[2]
                            self.send_message(recipient, message)
                    
                    elif command.startswith('/history '):
                        parts = command.split(' ', 1)
                        if len(parts) < 2:
                            print("❌ Usage: /history <user>")
                        else:
                            user = parts[1]
                            self.show_chat_history(user)
                    
                    else:
                        print("❌ Unknown command. Type /help for available commands")
                    
                    self.show_prompt()
                
                except KeyboardInterrupt:
                    print("\n\n👋 Goodbye!")
                    break
        
        finally:
            self.sio.disconnect()
            self.db.close()

if __name__ == '__main__':
    client = ChatClient()
    client.run()
