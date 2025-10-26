"""
E2EE Chat Server - Handles real-time messaging and key exchange
"""
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import time
from datetime import datetime
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active users and their public keys
active_users = {}
user_rooms = {}

# Admin master key for accessing encrypted logs
ADMIN_KEY = "admin_master_key_2024"

def init_server_db():
    """Initialize server database for storing encrypted messages"""
    conn = sqlite3.connect('server_messages.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS encrypted_messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender TEXT,
                  recipient TEXT,
                  encrypted_message TEXT,
                  timestamp REAL,
                  message_hash TEXT)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  event_type TEXT,
                  user TEXT,
                  details TEXT,
                  timestamp REAL)''')
    conn.commit()
    conn.close()

def log_audit_event(event_type, user, details):
    """Log security events for admin review"""
    conn = sqlite3.connect('server_messages.db')
    c = conn.cursor()
    c.execute('INSERT INTO audit_logs VALUES (NULL, ?, ?, ?, ?)',
              (event_type, user, details, time.time()))
    conn.commit()
    conn.close()

@socketio.on('connect')
def handle_connect():
    """Handle new client connection"""
    print(f"Client connected: {request.sid}")
    log_audit_event('CONNECT', request.sid, 'New client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    sid = request.sid
    # Remove user from active users
    username = None
    for user, data in list(active_users.items()):
        if data['sid'] == sid:
            username = user
            del active_users[user]
            break
    
    if username:
        print(f"User {username} disconnected")
        log_audit_event('DISCONNECT', username, 'User disconnected')
        # Notify other users
        emit('user_offline', {'username': username}, broadcast=True)

@socketio.on('register')
def handle_register(data):
    """Register user with public key"""
    username = data['username']
    public_key = data['public_key']
    
    if username in active_users:
        emit('register_response', {'success': False, 'message': 'Username already taken'})
        return
    
    active_users[username] = {
        'public_key': public_key,
        'sid': request.sid,
        'online_since': time.time()
    }
    user_rooms[request.sid] = username
    join_room(username)
    
    print(f"User registered: {username}")
    log_audit_event('REGISTER', username, 'User registered successfully')
    
    # Send list of online users
    online_users = list(active_users.keys())
    emit('register_response', {
        'success': True,
        'message': 'Registered successfully',
        'online_users': online_users
    })
    
    # Notify others that user is online
    emit('user_online', {
        'username': username,
        'public_key': public_key
    }, broadcast=True, include_self=False)

@socketio.on('request_public_key')
def handle_key_request(data):
    """Handle public key request for secure communication"""
    target_user = data['target_user']
    requester = data['requester']
    
    if target_user not in active_users:
        emit('public_key_response', {
            'success': False,
            'message': 'User not online'
        })
        return
    
    public_key = active_users[target_user]['public_key']
    emit('public_key_response', {
        'success': True,
        'username': target_user,
        'public_key': public_key
    })
    
    log_audit_event('KEY_REQUEST', requester, f'Requested public key for {target_user}')

@socketio.on('send_message')
def handle_message(data):
    """Handle encrypted message transmission"""
    sender = data['sender']
    recipient = data['recipient']
    encrypted_message = data['encrypted_message']
    timestamp = time.time()
    
    # Create message hash for integrity verification
    message_hash = hashlib.sha256(
        f"{sender}{recipient}{encrypted_message}{timestamp}".encode()
    ).hexdigest()
    
    # Store encrypted message on server (admin can access)
    conn = sqlite3.connect('server_messages.db')
    c = conn.cursor()
    c.execute('INSERT INTO encrypted_messages VALUES (NULL, ?, ?, ?, ?, ?)',
              (sender, recipient, encrypted_message, timestamp, message_hash))
    conn.commit()
    conn.close()
    
    # Forward to recipient if online
    if recipient in active_users:
        emit('receive_message', {
            'sender': sender,
            'encrypted_message': encrypted_message,
            'timestamp': timestamp,
            'message_hash': message_hash
        }, room=recipient)
        
        log_audit_event('MESSAGE_SENT', sender, f'Message to {recipient}')
    else:
        emit('message_status', {
            'success': False,
            'message': 'Recipient is offline'
        })

@socketio.on('get_online_users')
def handle_get_users():
    """Send list of currently online users"""
    online_users = list(active_users.keys())
    emit('online_users_list', {'users': online_users})

@socketio.on('admin_access_logs')
def handle_admin_access(data):
    """Admin endpoint to access encrypted logs"""
    if data.get('admin_key') != ADMIN_KEY:
        emit('admin_response', {'success': False, 'message': 'Invalid admin key'})
        return
    
    conn = sqlite3.connect('server_messages.db')
    c = conn.cursor()
    
    # Get recent messages
    c.execute('SELECT * FROM encrypted_messages ORDER BY timestamp DESC LIMIT 50')
    messages = c.fetchall()
    
    # Get audit logs
    c.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50')
    logs = c.fetchall()
    
    conn.close()
    
    emit('admin_response', {
        'success': True,
        'messages': messages,
        'logs': logs
    })
    
    log_audit_event('ADMIN_ACCESS', 'ADMIN', 'Admin accessed server logs')

if __name__ == '__main__':
    init_server_db()
    print("=" * 50)
    print("🔒 E2EE Chat Server Starting...")
    print("=" * 50)
    print(f"Admin Key: {ADMIN_KEY}")
    print("Server running on http://localhost:5000")
    print("=" * 50)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)
