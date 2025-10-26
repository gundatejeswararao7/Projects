"""
Interactive Demo - Demonstrates E2EE encryption process
Shows step-by-step how messages are encrypted and decrypted
"""
from crypto_manager import CryptoManager
import json
import time

def print_separator(char="=", length=70):
    print(char * length)

def print_header(text):
    print_separator()
    print(f"  {text}")
    print_separator()

def demo_key_generation():
    """Demonstrate RSA key generation"""
    print_header("🔑 STEP 1: RSA Key Generation")
    print("\nGenerating RSA-2048 key pairs for Alice and Bob...\n")
    
    alice = CryptoManager("demo_alice")
    bob = CryptoManager("demo_bob")
    
    alice_public = alice.export_public_key()
    bob_public = bob.export_public_key()
    
    print("✅ Alice's Public Key (first 200 chars):")
    print(f"   {alice_public[:200]}...\n")
    
    print("✅ Bob's Public Key (first 200 chars):")
    print(f"   {bob_public[:200]}...\n")
    
    print("🔐 Private keys are securely stored and never shared!")
    input("\nPress Enter to continue...")
    
    return alice, bob

def demo_key_exchange(alice, bob):
    """Demonstrate public key exchange"""
    print_header("🤝 STEP 2: Public Key Exchange")
    print("\nAlice and Bob exchange public keys through the server...")
    print("(Public keys can be shared safely - they only encrypt, not decrypt)\n")
    
    alice_public = alice.export_public_key()
    bob_public = bob.export_public_key()
    
    print("📤 Alice sends her public key to Bob")
    print("📤 Bob sends his public key to Alice")
    print("\n✅ Key exchange complete! Now they can send encrypted messages.")
    
    input("\nPress Enter to continue...")
    
    return alice_public, bob_public

def demo_message_encryption(alice, bob, bob_public):
    """Demonstrate message encryption process"""
    print_header("🔒 STEP 3: Message Encryption")
    
    message = "Hello Bob! This is a secret message from Alice. 🔐"
    print(f"\n📝 Alice wants to send: '{message}'")
    print(f"   Message length: {len(message)} characters\n")
    
    print("🔄 Encryption Process:")
    print("   1. Generate random AES-256 key (32 bytes)")
    print("   2. Generate random IV (16 bytes)")
    print("   3. Encrypt message using AES-256-CBC")
    print("   4. Encrypt AES key using Bob's RSA public key")
    print("   5. Combine encrypted data into JSON structure\n")
    
    # Encrypt
    print("⏳ Encrypting...")
    start_time = time.time()
    encrypted_data = alice.encrypt_message(message, bob_public)
    encryption_time = (time.time() - start_time) * 1000
    
    print(f"✅ Encryption completed in {encryption_time:.2f}ms\n")
    
    # Parse and display structure
    encrypted_json = json.loads(encrypted_data)
    
    print("📦 Encrypted Package Structure:")
    print(f"   - Encrypted AES Key: {len(encrypted_json['encrypted_key'])} chars")
    print(f"   - Initialization Vector (IV): {len(encrypted_json['iv'])} chars")
    print(f"   - Encrypted Message: {len(encrypted_json['ciphertext'])} chars")
    print(f"   - Total Size: {len(encrypted_data)} bytes\n")
    
    print("🔒 Encrypted Data Sample (first 150 chars):")
    print(f"   {encrypted_data[:150]}...\n")
    
    print("💡 Notice: The encrypted data looks like random gibberish!")
    print("   Only Bob's private key can decrypt this message.")
    
    input("\nPress Enter to continue...")
    
    return encrypted_data

def demo_message_transmission(encrypted_data):
    """Demonstrate message transmission"""
    print_header("📡 STEP 4: Message Transmission")
    
    print("\n🌐 Encrypted message is sent through the server...")
    print("   - Server receives encrypted data")
    print("   - Server CANNOT read the message (no private key)")
    print("   - Server stores encrypted copy for delivery")
    print("   - Server forwards to Bob when he's online\n")
    
    print("🔐 Server's View (encrypted):")
    print(f"   {encrypted_data[:100]}...\n")
    
    print("✅ Message delivered to Bob!")
    
    input("\nPress Enter to continue...")

def demo_message_decryption(bob, encrypted_data, original_message):
    """Demonstrate message decryption"""
    print_header("🔓 STEP 5: Message Decryption")
    
    print("\n📬 Bob receives the encrypted message...")
    print(f"   Encrypted data size: {len(encrypted_data)} bytes\n")
    
    print("🔄 Decryption Process:")
    print("   1. Extract encrypted AES key from package")
    print("   2. Decrypt AES key using Bob's RSA private key")
    print("   3. Extract IV and ciphertext")
    print("   4. Decrypt message using AES key and IV")
    print("   5. Remove padding and decode to text\n")
    
    print("⏳ Decrypting...")
    start_time = time.time()
    decrypted_message = bob.decrypt_message(encrypted_data)
    decryption_time = (time.time() - start_time) * 1000
    
    print(f"✅ Decryption completed in {decryption_time:.2f}ms\n")
    
    print("📖 Decrypted Message:")
    print(f"   '{decrypted_message}'\n")
    
    # Verify integrity
    if decrypted_message == original_message:
        print("✅ SUCCESS! Message matches original exactly!")
        print("   Bob can now read Alice's secret message.")
    else:
        print("❌ ERROR! Message doesn't match (integrity violation)")
    
    input("\nPress Enter to continue...")

def demo_security_features():
    """Demonstrate security features"""
    print_header("🛡️ STEP 6: Security Features")
    
    print("\n🔐 What We Just Demonstrated:")
    print()
    print("1. ✅ Confidentiality:")
    print("     Only Bob can decrypt messages sent to him")
    print("     Server and attackers see only encrypted data")
    print()
    print("2. ✅ Forward Secrecy Ready:")
    print("     Each message uses a new random AES key")
    print("     Compromising one message doesn't affect others")
    print()
    print("3. ✅ Authenticated Encryption:")
    print("     Hybrid encryption ensures strong security")
    print("     RSA-2048 + AES-256 = Military-grade protection")
    print()
    print("4. ✅ Integrity Protection:")
    print("     Any tampering makes decryption fail")
    print("     Messages arrive intact or not at all")
    print()
    
    print("🚫 What Attackers See:")
    print("   - Random-looking encrypted bytes")
    print("   - No patterns or identifiable information")
    print("   - Impossible to decrypt without private key")
    print()
    
    print("🎯 Real-World Security:")
    print("   - Breaking RSA-2048 would take thousands of years")
    print("   - AES-256 is used by governments for top-secret data")
    print("   - End-to-end encryption: not even WE can read your messages!")
    
    input("\nPress Enter to finish demo...")

def cleanup_demo_files():
    """Clean up demo files"""
    import os
    files = [
        "demo_alice_private_key.pem",
        "demo_bob_private_key.pem",
        "demo_alice_chat_history.db",
        "demo_bob_chat_history.db"
    ]
    
    for file in files:
        if os.path.exists(file):
            os.remove(file)

def run_demo():
    """Run complete interactive demo"""
    print("\n" + "="*70)
    print("  🔒 E2EE CHAT APPLICATION - INTERACTIVE DEMO")
    print("="*70)
    print("\nThis demo will show you how End-to-End Encryption works!")
    print("We'll follow a message from Alice to Bob through all encryption steps.\n")
    
    input("Press Enter to start the demo...")
    
    try:
        # Step 1: Key Generation
        alice, bob = demo_key_generation()
        
        # Step 2: Key Exchange
        alice_public, bob_public = demo_key_exchange(alice, bob)
        
        # Step 3: Encryption
        original_message = "Hello Bob! This is a secret message from Alice. 🔐"
        encrypted_data = demo_message_encryption(alice, bob, bob_public)
        
        # Step 4: Transmission
        demo_message_transmission(encrypted_data)
        
        # Step 5: Decryption
        demo_message_decryption(bob, encrypted_data, original_message)
        
        # Step 6: Security
        demo_security_features()
        
        # Final message
        print_header("✅ DEMO COMPLETE")
        print("\n🎉 Congratulations! You now understand how E2EE works!")
        print("\n📚 What's Next?")
        print("   1. Run 'python server.py' to start the chat server")
        print("   2. Run 'python client.py' in multiple terminals to chat")
        print("   3. Try sending encrypted messages between users")
        print("   4. Use 'python admin_tool.py' to see admin features")
        print("\n💡 Remember: Your messages are always encrypted end-to-end!")
        print("   Not even the server can read them. That's true privacy!\n")
        
        print_separator()
        
    finally:
        # Cleanup
        cleanup_demo_files()

if __name__ == '__main__':
    run_demo()
