#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Authentication module for the Secure Password Manager"""

import getpass
import binascii
from cryptography.fernet import Fernet
from password_manager.encryption import hash_password, create_system_key, create_user_key, generate_salt
from password_manager.utils import get_validated_input, get_machine_info

class AuthManager:
    """Manages authentication for the password manager"""
    
    def __init__(self, storage, session, logger=None):
        """
        Initialize the authentication manager
        
        Args:
            storage: PasswordStorage instance
            session: SessionManager instance
            logger: Optional logger instance
        """
        self.storage = storage
        self.session = session
        self.logger = logger
        self.fernet = None
    
    def create_master_account(self):
        """
        Create a new master username and password
        
        Returns:
            True if account was created successfully, False otherwise
        """
        print("\n=== Create Master Account ===")
        
        # Get and validate master username
        while True:
            username = input("Create master username (min 4 characters): ").strip()
            if len(username) < 4:
                print("⚠️ Username must be at least 4 characters long.")
                continue
            break
        
        # Get and validate master password
        while True:
            password = getpass.getpass("Create master password (min 8 characters): ")
            if len(password) < 8:
                print("⚠️ Master password must be at least 8 characters long.")
                continue
                
            confirm_password = getpass.getpass("Confirm master password: ")
            if password != confirm_password:
                print("⚠️ Passwords do not match. Please try again.")
                continue
                
            break
        
        # Create and save salt
        salt = generate_salt()
        if not self.storage.save_salt(salt):
            print("❌ Error: Could not save salt file.")
            return False
        
        # Create encryption key for securing the username and password hash
        system_key = create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        # Encrypt and save username
        encrypted_username = system_fernet.encrypt(username.encode())
        if not self.storage.save_master_username(encrypted_username):
            print("❌ Error: Could not save username file.")
            return False
        
        # Hash password with salt and encrypt the hash
        password_hash = hash_password(password, salt)
        encrypted_hash = system_fernet.encrypt(binascii.hexlify(password_hash))
        if not self.storage.save_password_hash(encrypted_hash):
            print("❌ Error: Could not save password hash file.")
            return False
        
        # Set up encryption key for passwords database
        self.fernet = create_user_key(username, password, salt)
        
        # Update session
        self.session.set_authenticated(username)
        
        print("✅ Master account created successfully!")
        return True
    
    def authenticate_master_account(self):
        """
        Authenticate with existing master username and password
        
        Returns:
            True if authentication successful, False otherwise
        """
        # Check if login is allowed based on previous attempts
        login_check = self.session.check_login_attempts()
        if not login_check["allowed"]:
            print(f"\n⛔ {login_check['message']}")
            return False
            
        print("\n=== Login ===")
        
        # Load salt
        salt = self.storage.load_salt()
        if not salt:
            print("❌ Error: Salt file missing. Password manager needs to be reset.")
            return False
            
        # Create system key for decryption
        system_key = create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        # Read encrypted username
        encrypted_username = self.storage.load_master_username()
        if not encrypted_username:
            print("❌ Error: Could not read master username.")
            self.session.update_login_attempts(False)
            return False
            
        try:
            stored_username = system_fernet.decrypt(encrypted_username).decode()
        except Exception as e:
            print(f"❌ Error: Could not decrypt master username: {e}")
            self.session.update_login_attempts(False)
            return False
        
        # Get max allowed attempts based on previous failures
        machine_info = get_machine_info()
        login_data = self.session._load_login_attempts()
        machine_id = machine_info["mac_address"]
        
        if machine_id in login_data:
            machine_data = login_data[machine_id]
            previous_lockouts = machine_data.get("previous_lockouts", 0)
            # Decrease max attempts based on previous lockouts
            max_attempts = max(1, self.session.max_login_attempts - previous_lockouts)
        else:
            max_attempts = self.session.max_login_attempts
        
        # Ask for login credentials
        attempts = 0
        
        while attempts < max_attempts:
            username = input("Enter username: ").strip()
            password = getpass.getpass("Enter password: ")
            attempts += 1
            
            # Check username first without revealing if it's correct
            if username != stored_username:
                # Don't reveal that username is wrong, just say credentials are invalid
                remaining = max_attempts - attempts
                login_attempt = self.session.update_login_attempts(False)
                
                # Use remaining from login tracking
                if "remaining_attempts" in login_attempt:
                    remaining = login_attempt["remaining_attempts"]
                
                if remaining > 0:
                    print(f"⚠️ Invalid credentials. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
                else:
                    print("⚠️ Invalid credentials. No attempts remaining.")
                    print(f"Your device has been locked out for {self.session.lockout_duration // 60} minutes.")
                return False
            
            # Hash the provided password
            provided_hash = hash_password(password, salt)
            
            # Read and decrypt stored hash
            encrypted_hash = self.storage.load_password_hash()
            if not encrypted_hash:
                print("❌ Error: Could not read password hash.")
                self.session.update_login_attempts(False)
                return False
                
            try:
                stored_hash = binascii.unhexlify(system_fernet.decrypt(encrypted_hash))
            except Exception as e:
                print(f"❌ Error: Could not decrypt password hash: {e}")
                self.session.update_login_attempts(False)
                return False
            
            # Compare hashes
            if provided_hash == stored_hash:
                # Set up encryption key for passwords database
                self.fernet = create_user_key(username, password, salt)
                self.session.set_authenticated(username)
                
                # Update login attempt tracking on success
                self.session.update_login_attempts(True)
                
                print(f"✅ Login successful. Welcome back, {username}!")
                return True
            else:
                # Password is wrong
                login_attempt = self.session.update_login_attempts(False)
                
                # Get remaining attempts from login tracking
                if "remaining_attempts" in login_attempt:
                    remaining = login_attempt["remaining_attempts"]
                else:
                    remaining = max_attempts - attempts
                
                if remaining > 0:
                    print(f"⚠️ Invalid password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
                else:
                    print("⚠️ Invalid password. No attempts remaining.")
                    print(f"Your device has been locked out for {self.session.lockout_duration // 60} minutes.")
                    return False
        
        print("❌ Too many failed login attempts. Your device has been locked out.")
        return False
    
    def require_auth_for_sensitive_action(self, action_name):
        """
        Require password re-authentication for sensitive actions
        
        Args:
            action_name: Description of the action requiring re-authentication
            
        Returns:
            True if re-authentication successful, False otherwise
        """
        if not self.session.session_authenticated:
            print("❌ You must be logged in to perform this action.")
            return False
            
        self.session.update_activity_time()
        print(f"\n⚠️ {action_name} is a sensitive operation that requires re-authentication.")
        
        # Load salt
        salt = self.storage.load_salt()
        if not salt:
            print("❌ Error: Salt file missing.")
            return False
        
        # Verify password again
        password = getpass.getpass("Enter your master password to continue: ")
        
        # Hash the provided password
        provided_hash = hash_password(password, salt)
        
        # Read and decrypt stored hash
        system_key = create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        encrypted_hash = self.storage.load_password_hash()
        if not encrypted_hash:
            print("❌ Error: Could not read password hash.")
            return False
            
        try:
            stored_hash = binascii.unhexlify(system_fernet.decrypt(encrypted_hash))
        except Exception as e:
            print(f"❌ Error: Could not decrypt password hash: {e}")
            return False
        
        # Compare hashes
        if provided_hash == stored_hash:
            return True
        else:
            print("❌ Invalid password. Action cancelled.")
            return False 