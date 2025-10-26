"""
Admin Tool - For authorized access to encrypted chat logs
Only accessible with admin master key
Complete implementation with all features
"""
import os
import sqlite3
from datetime import datetime
from db_manager import DatabaseManager
import getpass

ADMIN_KEY = 'admin_master_key_2024'

class AdminTool:
    def __init__(self):
        self.authenticated = False
    
    def authenticate(self):
        """Authenticate admin user"""
        print("\n" + "="*60)
        print("🔐 E2EE Chat - Admin Access Tool")
        print("="*60)
        
        admin_key = getpass.getpass("Enter Admin Master Key: ")
        
        if admin_key == ADMIN_KEY:
            self.authenticated = True
            print("✅ Authentication successful")
            return True
        else:
            print("❌ Authentication failed")
            return False
    
    def list_databases(self):
        """List all user databases"""
        db_files = [f for f in os.listdir('.') if f.endswith('_chat_history.db')]
        
        if not db_files:
            print("\n📭 No user databases found")
            return []
        
        print("\n📊 Available User Databases:")
        print("-" * 60)
        for i, db_file in enumerate(db_files, 1):
            username = db_file.replace('_chat_history.db', '')
            size = os.path.getsize(db_file)
            print(f"{i}. {username} ({size} bytes)")
        print("-" * 60)
        
        return db_files
    
    def view_user_messages(self, db_file):
        """View decrypted messages from user database"""
        try:
            messages = DatabaseManager.admin_decrypt_database(db_file, ADMIN_KEY)
            
            if not messages:
                print(f"\n📭 No messages found in {db_file}")
                return
            
            username = db_file.replace('_chat_history.db', '')
            print(f"\n{'='*80}")
            print(f"💬 Chat History for {username}")
            print(f"{'='*80}\n")
            
            for msg in messages:
                msg_id, sender, recipient, content, timestamp, msg_type = msg
                time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
                direction = "→" if msg_type == 'sent' else "←"
                print(f"[{msg_id}] [{time_str}]")
                print(f"    {sender} {direction} {recipient}")
                print(f"    Message: {content}")
                print(f"    Type: {msg_type}")
                print("-" * 80)
        
        except Exception as e:
            print(f"❌ Error accessing database: {e}")
    
    def view_server_logs(self):
        """View server audit logs"""
        if not os.path.exists('server_messages.db'):
            print("\n❌ Server database not found")
            return
        
        try:
            conn = sqlite3.connect('server_messages.db')
            c = conn.cursor()
            
            # Get audit logs
            c.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 50')
            logs = c.fetchall()
            
            if not logs:
                print("\n📭 No audit logs found")
                conn.close()
                return
            
            print(f"\n{'='*80}")
            print("🔍 Server Audit Logs")
            print(f"{'='*80}\n")
            
            for log in logs:
                log_id, event_type, user, details, timestamp = log
                time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                print(f"[{log_id}] [{time_str}] {event_type}")
                print(f"    User: {user}")
                print(f"    Details: {details}")
                print("-" * 80)
            
            conn.close()
        
        except Exception as e:
            print(f"❌ Error accessing server logs: {e}")
    
    def view_encrypted_messages(self):
        """View encrypted messages stored on server"""
        if not os.path.exists('server_messages.db'):
            print("\n❌ Server database not found")
            return
        
        try:
            conn = sqlite3.connect('server_messages.db')
            c = conn.cursor()
            
            c.execute('SELECT * FROM encrypted_messages ORDER BY timestamp DESC LIMIT 20')
            messages = c.fetchall()
            
            if not messages:
                print("\n📭 No encrypted messages found")
                conn.close()
                return
            
            print(f"\n{'='*80}")
            print("🔒 Encrypted Messages on Server")
            print(f"{'='*80}\n")
            
            for msg in messages:
                msg_id, sender, recipient, encrypted_msg, timestamp, msg_hash = msg
                time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
                print(f"[{msg_id}] [{time_str}]")
                print(f"    From: {sender} → To: {recipient}")
                print(f"    Hash: {msg_hash[:32]}...")
                print(f"    Encrypted Data: {encrypted_msg[:80]}...")
                print("-" * 80)
            
            conn.close()
        
        except Exception as e:
            print(f"❌ Error accessing encrypted messages: {e}")
    
    def export_all_data(self):
        """Export all data to a report file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f"admin_report_{timestamp}.txt"
        
        try:
            with open(report_file, 'w') as f:
                f.write("="*80 + "\n")
                f.write("E2EE Chat Application - Admin Report\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                # List all users
                db_files = [f for f in os.listdir('.') if f.endswith('_chat_history.db')]
                f.write(f"Total Users: {len(db_files)}\n")
                f.write("\nUser List:\n")
                for db_file in db_files:
                    username = db_file.replace('_chat_history.db', '')
                    f.write(f"  - {username}\n")
                
                f.write("\n" + "="*80 + "\n\n")
                
                # Export each user's messages
                for db_file in db_files:
                    username = db_file.replace('_chat_history.db', '')
                    f.write(f"\n{'='*80}\n")
                    f.write(f"Messages for: {username}\n")
                    f.write(f"{'='*80}\n\n")
                    
                    messages = DatabaseManager.admin_decrypt_database(db_file, ADMIN_KEY)
                    
                    if messages:
                        for msg in messages:
                            msg_id, sender, recipient, content, timestamp, msg_type = msg
                            time_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                            f.write(f"[{time_str}] {sender} → {recipient}\n")
                            f.write(f"Message: {content}\n")
                            f.write(f"Type: {msg_type}\n")
                            f.write("-" * 80 + "\n")
                    else:
                        f.write("No messages found.\n")
                
                f.write("\n" + "="*80 + "\n")
            
            print(f"✅ Report exported to: {report_file}")
        
        except Exception as e:
            print(f"❌ Error exporting data: {e}")
    
    def run(self):
        """Main admin tool loop"""
        if not self.authenticate():
            return
        
        while True:
            print("\n" + "="*60)
            print("🔐 Admin Menu")
            print("="*60)
            print("1. View User Databases")
            print("2. View Specific User Messages")
            print("3. View Server Audit Logs")
            print("4. View Encrypted Messages on Server")
            print("5. Export All Data to Report")
            print("6. Exit")
            print("="*60)
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.list_databases()
            
            elif choice == '2':
                db_files = self.list_databases()
                if db_files:
                    try:
                        num = int(input("\nSelect user number: "))
                        if 1 <= num <= len(db_files):
                            self.view_user_messages(db_files[num-1])
                        else:
                            print("❌ Invalid selection")
                    except ValueError:
                        print("❌ Invalid input")
            
            elif choice == '3':
                self.view_server_logs()
            
            elif choice == '4':
                self.view_encrypted_messages()
            
            elif choice == '5':
                self.export_all_data()
            
            elif choice == '6':
                print("\n👋 Goodbye!")
                break
            
            else:
                print("❌ Invalid option")

if __name__ == '__main__':
    admin = AdminTool()
    admin.run()
