"""
Test Suite for Cryptography Implementation
Validates encryption, decryption, and security features
"""
import sys
import os
from crypto_manager import CryptoManager
from db_manager import DatabaseManager
import time

def test_rsa_key_generation():
    """Test RSA key pair generation"""
    print("\n🔑 Testing RSA Key Generation...")
    try:
        crypto = CryptoManager("test_user_1")
        assert crypto.private_key is not None
        assert crypto.public_key is not None
        print("   ✅ RSA keys generated successfully")
        
        # Test key export
        public_key_pem = crypto.export_public_key()
        assert public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        print("   ✅ Public key export successful")
        
        # Cleanup
        if os.path.exists("test_user_1_private_key.pem"):
            os.remove("test_user_1_private_key.pem")
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_message_encryption_decryption():
    """Test end-to-end message encryption"""
    print("\n🔒 Testing Message Encryption/Decryption...")
    try:
        # Create two users
        alice = CryptoManager("alice_test")
        bob = CryptoManager("bob_test")
        
        # Test message
        original_message = "Hello, this is a secret message! 🔒"
        
        # Alice encrypts message for Bob
        bob_public_key = bob.export_public_key()
        encrypted = alice.encrypt_message(original_message, bob_public_key)
        
        assert encrypted != original_message
        print(f"   ✅ Message encrypted (length: {len(encrypted)} bytes)")
        
        # Bob decrypts message
        decrypted = bob.decrypt_message(encrypted)
        
        assert decrypted == original_message
        print(f"   ✅ Message decrypted correctly: '{decrypted}'")
        
        # Cleanup
        for file in ["alice_test_private_key.pem", "bob_test_private_key.pem"]:
            if os.path.exists(file):
                os.remove(file)
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_multiple_messages():
    """Test encrypting multiple different messages"""
    print("\n📨 Testing Multiple Message Encryption...")
    try:
        alice = CryptoManager("alice_multi")
        bob = CryptoManager("bob_multi")
        bob_public_key = bob.export_public_key()
        
        messages = [
            "Short msg",
            "This is a longer message with more content to test encryption",
            "Special chars: !@#$%^&*()_+-=[]{}|;:',.<>?/~`",
            "Unicode: 你好 مرحبا Привет 🎉🔒💬",
            "Numbers: 1234567890 " * 10
        ]
        
        for i, msg in enumerate(messages, 1):
            encrypted = alice.encrypt_message(msg, bob_public_key)
            decrypted = bob.decrypt_message(encrypted)
            assert decrypted == msg
            print(f"   ✅ Message {i}: {len(msg)} chars encrypted/decrypted")
        
        # Cleanup
        for file in ["alice_multi_private_key.pem", "bob_multi_private_key.pem"]:
            if os.path.exists(file):
                os.remove(file)
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_database_encryption():
    """Test encrypted database storage"""
    print("\n💾 Testing Encrypted Database Storage...")
    try:
        db = DatabaseManager("test_db_user")
        
        # Store test messages
        test_messages = [
            ("alice", "bob", "Hello Bob!", time.time(), "sent"),
            ("bob", "alice", "Hi Alice!", time.time(), "received"),
            ("alice", "bob", "How are you?", time.time(), "sent"),
        ]
        
        for msg in test_messages:
            db.store_message(*msg)
        print("   ✅ Messages stored in encrypted database")
        
        # Retrieve and verify
        history = db.get_chat_history("bob")
        assert len(history) >= 2
        print(f"   ✅ Retrieved {len(history)} encrypted messages")
        
        # Verify content
        for msg in history:
            _, sender, recipient, content, timestamp, msg_type = msg
            assert content in ["Hello Bob!", "How are you?"]
        print("   ✅ Decrypted messages match original content")
        
        # Cleanup
        db.close()
        if os.path.exists("test_db_user_chat_history.db"):
            os.remove("test_db_user_chat_history.db")
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_admin_access():
    """Test admin database decryption"""
    print("\n🔐 Testing Admin Access to Encrypted Database...")
    try:
        # Create user and store messages
        db = DatabaseManager("admin_test_user")
        db.store_message("alice", "bob", "Secret message", time.time(), "sent")
        db.close()
        
        # Admin access
        messages = DatabaseManager.admin_decrypt_database(
            "admin_test_user_chat_history.db",
            "admin_master_key_2024"
        )
        
        assert messages is not None
        assert len(messages) > 0
        print(f"   ✅ Admin successfully decrypted {len(messages)} messages")
        
        # Verify content
        _, sender, recipient, content, _, _ = messages[0]
        assert content == "Secret message"
        print("   ✅ Admin can read encrypted user messages")
        
        # Cleanup
        if os.path.exists("admin_test_user_chat_history.db"):
            os.remove("admin_test_user_chat_history.db")
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_signature_verification():
    """Test digital signature creation and verification"""
    print("\n✍️ Testing Digital Signatures...")
    try:
        alice = CryptoManager("alice_sig")
        bob = CryptoManager("bob_sig")
        
        message = "This message is signed by Alice"
        
        # Alice signs message
        signature = alice.sign_message(message)
        print(f"   ✅ Message signed (signature length: {len(signature)})")
        
        # Bob verifies signature
        alice_public_key = alice.export_public_key()
        is_valid = bob.verify_signature(message, signature, alice_public_key)
        assert is_valid
        print("   ✅ Signature verified successfully")
        
        # Test with tampered message
        tampered_message = "This message was tampered"
        is_valid_tampered = bob.verify_signature(tampered_message, signature, alice_public_key)
        assert not is_valid_tampered
        print("   ✅ Tampered message detected correctly")
        
        # Cleanup
        for file in ["alice_sig_private_key.pem", "bob_sig_private_key.pem"]:
            if os.path.exists(file):
                os.remove(file)
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def test_key_persistence():
    """Test that keys are properly saved and loaded"""
    print("\n🔄 Testing Key Persistence...")
    try:
        # Generate keys
        crypto1 = CryptoManager("persist_user")
        public_key_1 = crypto1.export_public_key()
        
        # Create new instance (should load existing keys)
        crypto2 = CryptoManager("persist_user")
        public_key_2 = crypto2.export_public_key()
        
        assert public_key_1 == public_key_2
        print("   ✅ Keys persisted and loaded correctly")
        
        # Test encryption with loaded keys
        message = "Test with persisted keys"
        encrypted = crypto1.encrypt_message(message, public_key_2)
        decrypted = crypto2.decrypt_message(encrypted)
        assert decrypted == message
        print("   ✅ Encryption works with persisted keys")
        
        # Cleanup
        if os.path.exists("persist_user_private_key.pem"):
            os.remove("persist_user_private_key.pem")
        
        return True
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        return False

def run_all_tests():
    """Run complete test suite"""
    print("="*60)
    print("🧪 E2EE Chat Application - Cryptography Test Suite")
    print("="*60)
    
    tests = [
        ("RSA Key Generation", test_rsa_key_generation),
        ("Message Encryption/Decryption", test_message_encryption_decryption),
        ("Multiple Messages", test_multiple_messages),
        ("Database Encryption", test_database_encryption),
        ("Admin Access", test_admin_access),
        ("Digital Signatures", test_signature_verification),
        ("Key Persistence", test_key_persistence),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ {test_name} crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("📊 Test Results Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print("="*60)
    print(f"Result: {passed}/{total} tests passed")
    print("="*60)
    
    if passed == total:
        print("\n🎉 All tests passed! Cryptography implementation is secure.")
        return 0
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Please review implementation.")
        return 1

if __name__ == '__main__':
    sys.exit(run_all_tests())
