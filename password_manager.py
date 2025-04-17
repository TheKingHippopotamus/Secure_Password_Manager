#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Secure Password Manager

This program allows you to:
1. Generate strong, random passwords
2. Store passwords securely (encrypted) in a local file
3. Retrieve passwords when needed
4. Search for passwords by username or website

All data is stored locally in encrypted form at ~/.password_manager/.passwords.enc
"""

import random
import hashlib
import time
import json
import os
import base64
import getpass
import re
import threading
import binascii
import logging
import socket
import platform
import uuid
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define character sets for password generation
LOWERCASE = list("abcdefghijklmnopqrstuvwxyz")
UPPERCASE = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGITS = list("0123456789")
SPECIAL_CHARS = list("!@#$%^*)(")

class SecurePasswordManager:
    def __init__(self):
        """Initialize the password manager with file paths and encryption setup"""
        # Set up storage directory and files
        self.data_dir = os.path.join(os.path.expanduser("~"), ".password_manager")
        self.passwords_file = os.path.join(self.data_dir, ".passwords.enc")
        self.salt_file = os.path.join(self.data_dir, "salt.bin")
        self.username_file = os.path.join(self.data_dir, ".master_user.enc")
        self.password_hash_file = os.path.join(self.data_dir, ".master_hash.enc")
        self.login_attempts_file = os.path.join(self.data_dir, ".login_attempts.dat")
        self.log_file = os.path.join(self.data_dir, "password_manager.log")
        
        # Create data directory if it doesn't exist
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            print(f"Created data directory at: {self.data_dir}")
        
        # Setup logger
        self._setup_logger()
        
        # Initialize master account, encryption and session timeout
        self.fernet = None
        self.username = None
        self.session_authenticated = False
        self.last_activity_time = time.time()
        self.session_timeout = 30 * 60  # 30 minutes
        
        # Login attempt tracking
        self.max_login_attempts = 3
        self.lockout_duration = 15 * 60  # 15 minutes
        
        # Initialize
        self.initialize_master_account()
        
        # Start session timeout checker
        self.start_session_checker()
        
        # Log information only if authenticated
        if self.session_authenticated:
            self.logger.info(f"Password Manager initialized. Data directory: {self.data_dir}")
    
    def _setup_logger(self):
        """Set up the logging system"""
        # Create logger
        self.logger = logging.getLogger("SecurePasswordManager")
        self.logger.setLevel(logging.INFO)
        
        # Create file handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Add handler to logger
        self.logger.addHandler(file_handler)
    
    def _get_machine_info(self):
        """Get detailed information about the current machine"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            os_info = f"{platform.system()} {platform.release()}"
            mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                                   for elements in range(0, 8*6, 8)][::-1])
            
            return {
                "hostname": hostname,
                "ip_address": ip_address,
                "os_info": os_info,
                "mac_address": mac_address,
                "username": os.getlogin(),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            self.logger.error(f"Error getting machine info: {e}")
            return {
                "error": str(e),
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    
    def _check_login_attempts(self):
        """Check if the current machine is allowed to attempt login"""
        machine_info = self._get_machine_info()
        machine_id = machine_info["mac_address"]
        
        # Load login attempts data
        login_data = self._load_login_attempts()
        
        # Check if machine is locked out
        if machine_id in login_data:
            machine_data = login_data[machine_id]
            
            # If lockout time exists and still valid
            if "lockout_until" in machine_data:
                lockout_time = datetime.strptime(machine_data["lockout_until"], "%Y-%m-%d %H:%M:%S")
                
                if datetime.now() < lockout_time:
                    # Still locked out
                    remaining = (lockout_time - datetime.now()).total_seconds() / 60
                    self.logger.warning(f"Login blocked - device is locked out for {remaining:.1f} more minutes")
                    return {
                        "allowed": False,
                        "remaining_time": remaining,
                        "message": f"Login blocked. Try again in {remaining:.1f} minutes."
                    }
                else:
                    # Lockout expired, reset attempts but keep track of previous failures
                    machine_data["failed_attempts"] = 0
                    machine_data["previous_lockouts"] += 1
                    machine_data.pop("lockout_until", None)
                    login_data[machine_id] = machine_data
                    self._save_login_attempts(login_data)
        
        return {"allowed": True}
    
    def _update_login_attempts(self, success):
        """Update the login attempts tracking after a login attempt"""
        machine_info = self._get_machine_info()
        machine_id = machine_info["mac_address"]
        
        # Load existing data
        login_data = self._load_login_attempts()
        
        # Get or create machine data
        if machine_id not in login_data:
            machine_data = {
                "machine_info": machine_info,
                "failed_attempts": 0,
                "previous_lockouts": 0,
                "last_attempt": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            machine_data = login_data[machine_id]
            machine_data["last_attempt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            machine_data["machine_info"] = machine_info  # Update machine info
        
        # Update based on success/failure
        if success:
            # Reset failed attempts on success
            machine_data["failed_attempts"] = 0
            if "remaining_attempts" in machine_data:
                machine_data.pop("remaining_attempts")
            self.logger.info(f"Successful login from {machine_info['hostname']} ({machine_info['ip_address']})")
        else:
            # Track failed attempts
            machine_data["failed_attempts"] += 1
            
            # Calculate remaining attempts based on previous lockouts
            max_attempts = max(1, self.max_login_attempts - machine_data.get("previous_lockouts", 0))
            remaining = max_attempts - machine_data["failed_attempts"]
            
            machine_data["remaining_attempts"] = remaining
            
            self.logger.warning(
                f"Failed login attempt from {machine_info['hostname']} "
                f"({machine_info['ip_address']}). "
                f"Attempts remaining: {remaining}"
            )
            
            # If no remaining attempts, lock out the machine
            if remaining <= 0:
                lockout_time = datetime.now() + timedelta(seconds=self.lockout_duration)
                machine_data["lockout_until"] = lockout_time.strftime("%Y-%m-%d %H:%M:%S")
                self.logger.warning(
                    f"Device locked out until {machine_data['lockout_until']} "
                    f"due to too many failed attempts"
                )
        
        # Save updated data
        login_data[machine_id] = machine_data
        self._save_login_attempts(login_data)
        
        return machine_data
    
    def _load_login_attempts(self):
        """Load the login attempts data"""
        if os.path.exists(self.login_attempts_file):
            try:
                with open(self.login_attempts_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_login_attempts(self, data):
        """Save the login attempts data"""
        with open(self.login_attempts_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def initialize_master_account(self):
        """Set up master username and password if not already created, then authenticate"""
        # Check if master account exists (both username and password hash files)
        account_exists = (os.path.exists(self.username_file) and
                         os.path.exists(self.password_hash_file) and
                         os.path.exists(self.salt_file))
        
        if account_exists:
            # Don't log anything since not authenticated yet
            if not os.path.isfile(self.login_attempts_file):
                with open(self.login_attempts_file, 'w') as f:
                    json.dump({}, f)
            
            # Don't display "Please login" unless login is allowed
            login_check = self._check_login_attempts()
            if login_check["allowed"]:
                print("\nMaster account exists. Please login.")
                self.authenticate_master_account()
            else:
                print(f"\n⛔ {login_check['message']}")
                self.session_authenticated = False
        else:
            print("\nWelcome! Let's set up your master account to secure your passwords.")
            self.create_master_account()
    
    def create_master_account(self):
        """Create a new master username and password"""
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
        salt = os.urandom(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Create encryption key for securing the username and password hash
        system_key = self._create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        # Encrypt and save username
        encrypted_username = system_fernet.encrypt(username.encode())
        with open(self.username_file, 'wb') as f:
            f.write(encrypted_username)
        
        # Hash password with salt and encrypt the hash
        password_hash = self._hash_password(password, salt)
        encrypted_hash = system_fernet.encrypt(binascii.hexlify(password_hash))
        with open(self.password_hash_file, 'wb') as f:
            f.write(encrypted_hash)
        
        # Set up encryption key for passwords database
        self._setup_encryption(username, password, salt)
        
        print("✅ Master account created successfully!")
        self.session_authenticated = True
        self.username = username
        self.last_activity_time = time.time()
    
    def authenticate_master_account(self):
        """Authenticate with existing master username and password"""
        # Check if login is allowed based on previous attempts
        login_check = self._check_login_attempts()
        if not login_check["allowed"]:
            print(f"\n⛔ {login_check['message']}")
            return False
            
        print("\n=== Login ===")
        
        # Only proceed if salt file exists
        if not os.path.exists(self.salt_file):
            print("❌ Error: Salt file missing. Password manager needs to be reset.")
            return False
            
        # Read salt
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
            
        # Create system key for decryption
        system_key = self._create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        # Read encrypted username
        try:
            with open(self.username_file, 'rb') as f:
                encrypted_username = f.read()
            stored_username = system_fernet.decrypt(encrypted_username).decode()
        except:
            print("❌ Error: Could not read master username.")
            self._update_login_attempts(False)
            return False
        
        # Get max allowed attempts based on previous failures
        machine_info = self._get_machine_info()
        login_data = self._load_login_attempts()
        machine_id = machine_info["mac_address"]
        
        if machine_id in login_data:
            machine_data = login_data[machine_id]
            previous_lockouts = machine_data.get("previous_lockouts", 0)
            # Decrease max attempts based on previous lockouts
            max_attempts = max(1, self.max_login_attempts - previous_lockouts)
        else:
            max_attempts = self.max_login_attempts
        
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
                login_attempt = self._update_login_attempts(False)
                
                # Use remaining from login tracking
                if "remaining_attempts" in login_attempt:
                    remaining = login_attempt["remaining_attempts"]
                
                if remaining > 0:
                    print(f"⚠️ Invalid credentials. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
                else:
                    print("⚠️ Invalid credentials. No attempts remaining.")
                    print(f"Your device has been locked out for {self.lockout_duration // 60} minutes.")
                    return False
                continue
            
            # Hash the provided password
            provided_hash = self._hash_password(password, salt)
            
            # Read and decrypt stored hash
            try:
                with open(self.password_hash_file, 'rb') as f:
                    encrypted_hash = f.read()
                stored_hash = binascii.unhexlify(system_fernet.decrypt(encrypted_hash))
            except:
                print("❌ Error: Could not read password hash.")
                self._update_login_attempts(False)
                return False
            
            # Compare hashes
            if provided_hash == stored_hash:
                # Set up encryption key for passwords database
                self._setup_encryption(username, password, salt)
                self.session_authenticated = True
                self.username = username
                self.last_activity_time = time.time()
                
                # Update login attempt tracking on success
                self._update_login_attempts(True)
                
                print(f"✅ Login successful. Welcome back, {username}!")
                return True
            else:
                # Password is wrong
                login_attempt = self._update_login_attempts(False)
                
                # Get remaining attempts from login tracking
                if "remaining_attempts" in login_attempt:
                    remaining = login_attempt["remaining_attempts"]
                else:
                    remaining = max_attempts - attempts
                
                if remaining > 0:
                    print(f"⚠️ Invalid password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.")
                else:
                    print("⚠️ Invalid password. No attempts remaining.")
                    print(f"Your device has been locked out for {self.lockout_duration // 60} minutes.")
                    return False
        
        print("❌ Too many failed login attempts. Your device has been locked out.")
        return False
    
    def _create_system_key(self, salt):
        """Create a system-specific key for encrypting master credentials"""
        # Use machine-specific information plus salt to create a key
        machine_id = self._get_machine_id()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
        return key
    
    def _get_machine_id(self):
        """Get a unique machine identifier, or fallback to a default"""
        try:
            # Try to get machine-specific identifier
            if os.path.exists('/etc/machine-id'):
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            elif os.path.exists('/var/lib/dbus/machine-id'):
                with open('/var/lib/dbus/machine-id', 'r') as f:
                    return f.read().strip()
            else:
                # Fallback to username and hostname
                return f"{os.getlogin()}@{os.uname().nodename}"
        except:
            # Ultimate fallback
            return "secure_password_manager_default_key"
    
    def _hash_password(self, password, salt):
        """Create a secure hash of the password using the salt"""
        hash_obj = hashlib.sha256()
        hash_obj.update(salt)
        hash_obj.update(password.encode())
        return hash_obj.digest()
    
    def _setup_encryption(self, username, password, salt):
        """Set up the encryption key for the passwords database"""
        # Create a combined key using both username and password
        combined_key = username + ":" + password
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(combined_key.encode()))
        self.fernet = Fernet(key)
    
    def start_session_checker(self):
        """Start a background thread to check for session timeout"""
        def check_session():
            while True:
                time.sleep(60)  # Check every minute
                if self.session_authenticated:
                    elapsed = time.time() - self.last_activity_time
                    if elapsed > self.session_timeout:
                        print("\n⚠️ Session timed out due to inactivity (30 minutes).")
                        print("Please authenticate again to continue.")
                        self.session_authenticated = False
        
        # Start the thread as daemon so it doesn't prevent program exit
        session_thread = threading.Thread(target=check_session, daemon=True)
        session_thread.start()
    
    def update_activity_time(self):
        """Update the last activity timestamp"""
        self.last_activity_time = time.time()
        
    def require_auth_for_sensitive_action(self, action_name):
        """Require password re-authentication for sensitive actions"""
        if not self.session_authenticated:
            print("❌ You must be logged in to perform this action.")
            return False
            
        self.update_activity_time()
        print(f"\n⚠️ {action_name} is a sensitive operation that requires re-authentication.")
        
        # Verify password again
        password = getpass.getpass("Enter your master password to continue: ")
        
        # Get salt
        with open(self.salt_file, 'rb') as f:
            salt = f.read()
            
        # Hash the provided password
        provided_hash = self._hash_password(password, salt)
        
        # Read and decrypt stored hash
        system_key = self._create_system_key(salt)
        system_fernet = Fernet(system_key)
        
        try:
            with open(self.password_hash_file, 'rb') as f:
                encrypted_hash = f.read()
            stored_hash = binascii.unhexlify(system_fernet.decrypt(encrypted_hash))
        except:
            print("❌ Error: Could not read password hash.")
            return False
        
        # Compare hashes
        if provided_hash == stored_hash:
            return True
        else:
            print("❌ Invalid password. Action cancelled.")
            return False
    
    def generate_password(self, length=15, use_special=True, use_uppercase=True, use_digits=True):
        """Generate a strong random password with selected character types"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to generate passwords.")
            return None
            
        self.update_activity_time()
        
        # Log password generation (without the actual password)
        self.logger.info(f"Generating password (length={length}, special={use_special}, uppercase={use_uppercase}, digits={use_digits})")
            
        # Validate inputs
        if not isinstance(length, int) or length <= 0:
            print("⚠️ Invalid length. Using default length of 15.")
            length = 15
            
        # Build character set based on options
        all_chars = LOWERCASE.copy()
        
        if use_uppercase:
            all_chars += UPPERCASE
        
        if use_digits:
            all_chars += DIGITS
        
        if use_special:
            all_chars += SPECIAL_CHARS
        
        # Ensure we have enough character diversity
        if len(all_chars) < 30:
            print("Warning: Limited character set may reduce password strength")
            
        # Create entropy for password generation
        binary_soup = self._create_entropy(all_chars)
        
        # Create password with required character types
        password = self._create_diverse_password(
            length, 
            all_chars,
            use_lowercase=True,
            use_uppercase=use_uppercase,
            use_digits=use_digits,
            use_special=use_special
        )
        
        # Calculate strength
        strength = self._calculate_password_strength(password)
        
        return {
            'password': password,
            'strength': strength,
            'length': len(password),
            'character_types': {
                'lowercase': any(c in LOWERCASE for c in password),
                'uppercase': any(c in UPPERCASE for c in password),
                'digits': any(c in DIGITS for c in password),
                'special': any(c in SPECIAL_CHARS for c in password)
            }
        }
    
    def _create_entropy(self, chars):
        """Create a source of randomness for password generation"""
        # Mix various sources of randomness
        binary_soup = ""
        time_value = str(time.time())
        
        # Add character values
        for char in chars:
            value = ord(char)
            binary = bin(value)[2:].zfill(16 if value > 127 else 8)
            binary_soup += binary
        
        # Add current time
        binary_soup += bin(int(time.time() * 1000000))[2:]
        
        # Hash the mixture for better randomness
        hash_obj = hashlib.sha512((binary_soup + time_value).encode())
        
        return hash_obj.digest()
    
    def _create_diverse_password(self, length, all_chars, **char_types):
        """Create a password with at least one character from each required type"""
        password = ""
        
        # Start with one character from each required type
        if char_types.get('use_lowercase', False) and LOWERCASE:
            password += random.choice(LOWERCASE)
            
        if char_types.get('use_uppercase', False) and UPPERCASE:
            password += random.choice(UPPERCASE)
            
        if char_types.get('use_digits', False) and DIGITS:
            password += random.choice(DIGITS)
            
        if char_types.get('use_special', False) and SPECIAL_CHARS:
            password += random.choice(SPECIAL_CHARS)
        
        # Fill remaining characters randomly
        while len(password) < length:
            password += random.choice(all_chars)
        
        # Shuffle the password characters for randomness
        password_list = list(password)
        random.shuffle(password_list)
        password = ''.join(password_list)
        
        return password
    
    def _calculate_password_strength(self, password):
        """Calculate password strength score"""
        score = 0
        
        # Length score
        if len(password) >= 16:
            score += 30
        elif len(password) >= 12:
            score += 20
        elif len(password) >= 8:
            score += 10
        
        # Character diversity score
        if any(c in LOWERCASE for c in password):
            score += 10
        if any(c in UPPERCASE for c in password):
            score += 15
        if any(c in DIGITS for c in password):
            score += 15
        if any(c in SPECIAL_CHARS for c in password):
            score += 20
        
        # Rating
        if score >= 80:
            return "Excellent"
        elif score >= 60:
            return "Very Strong"
        elif score >= 40:
            return "Strong"
        elif score >= 25:
            return "Medium"
        else:
            return "Weak"
    
    def save_password(self, username, website, password, notes=""):
        """Save a password to the encrypted storage file"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to save passwords.")
            return False
            
        self.update_activity_time()
            
        # Validate inputs
        if not username or not website or not password:
            print("❌ Error: Username, website, and password are required.")
            return False
            
        if not self.fernet:
            print("❌ Error: Encryption not initialized. Can't save password.")
            return False
        
        # Load existing passwords
        passwords = self.load_passwords()
        
        # Create new password entry
        entry = {
            'username': username,
            'website': website,
            'password': password,
            'notes': notes,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Check if this entry would be a duplicate
        for existing in passwords:
            if (existing['username'] == username and 
                existing['website'] == website):
                replace = self._get_validated_input(
                    "Entry already exists. Replace? (y/n): ", 
                    valid_options=['y', 'n'], 
                    default='n'
                )
                if replace != 'y':
                    print("Password not saved.")
                    return False
                else:
                    passwords.remove(existing)
                    self.logger.info(f"Replaced existing password for {username} at {website}")
                    break
        
        # Add the new entry
        passwords.append(entry)
        
        # Encrypt and save
        try:
            encrypted_data = self.fernet.encrypt(json.dumps(passwords).encode())
            with open(self.passwords_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Log but don't include the password
            self.logger.info(f"Saved password for {username} at {website}")
            
            print(f"✅ Password saved successfully for {username} at {website}")
            return True
        except Exception as e:
            error_msg = f"Error saving password: {e}"
            self.logger.error(error_msg)
            print(f"❌ {error_msg}")
            return False
    
    def load_passwords(self):
        """Load and decrypt passwords from the storage file"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to access passwords.")
            return []
            
        self.update_activity_time()
            
        if not self.fernet:
            print("❌ Error: Encryption not initialized. Can't load passwords.")
            return []
        
        # Check if passwords file exists
        if not os.path.exists(self.passwords_file):
            print(f"No password file found at: {self.passwords_file}")
            return []
        
        try:
            # Read and decrypt data
            with open(self.passwords_file, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            print(f"❌ Error: Failed to decrypt data: {e}")
            print("   This usually means the master password was incorrect.")
            return []
    
    def find_password(self, search_term):
        """Search for passwords by username or website"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to search passwords.")
            return []
            
        self.update_activity_time()
        
        # Log the search
        self.logger.info(f"Searching for passwords with term: {search_term}")
            
        if not search_term:
            print("Please enter a search term.")
            return []
            
        # Require at least 3 characters for search
        if len(search_term) < 3:
            print("⚠️ Search term must be at least 3 characters long.")
            return []
            
        passwords = self.load_passwords()
        results = []
        
        search_term = search_term.lower()
        
        for entry in passwords:
            # Extract domain name from website URL
            website = entry['website']
            domain = self._extract_domain_name(website).lower()
            
            # Extract username part (before @) from email addresses
            username = entry['username'].lower()
            username_part = username.split('@')[0] if '@' in username else username
            
            # Check if search term matches:
            # 1. The extracted domain name of the website
            # 2. The username part (before @) of the email
            if (search_term == domain or  # Exact match for domain
                domain.startswith(search_term) or  # Domain starts with search term
                search_term in username_part):  # Search term in username part
                results.append(entry)
        
        # Log search results count (but not the actual results)
        self.logger.info(f"Found {len(results)} results for search term: {search_term}")
        
        return results
    
    def _extract_domain_name(self, url):
        """Extract the domain name from a URL, removing protocol and common TLDs"""
        # Remove protocol (http://, https://)
        if '://' in url:
            url = url.split('://', 1)[1]
        
        # Remove "www." if present
        if url.startswith('www.'):
            url = url[4:]
        
        # Remove path after domain (everything after first /)
        if '/' in url:
            url = url.split('/', 1)[0]
        
        # Remove port if present (everything after :)
        if ':' in url:
            url = url.split(':', 1)[0]
        
        # Remove common TLDs
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co', '.io']
        for tld in common_tlds:
            if url.endswith(tld):
                url = url[:-len(tld)]
                break
            
        return url
    
    def list_websites(self):
        """List all websites in the password store"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to list websites.")
            return []
            
        self.update_activity_time()
            
        passwords = self.load_passwords()
        websites = set()
        
        for entry in passwords:
            websites.add(entry['website'])
        
        return sorted(list(websites))
    
    def delete_password(self, username, website):
        """Delete a specific password entry"""
        # Validate session and require re-authentication
        if not self.require_auth_for_sensitive_action("Password deletion"):
            return False
            
        if not username or not website:
            print("Username and website are required.")
            return False
            
        passwords = self.load_passwords()
        initial_count = len(passwords)
        
        # Find and remove matching entries
        passwords = [entry for entry in passwords 
                    if not (entry['username'] == username and 
                           entry['website'] == website)]
        
        if len(passwords) < initial_count:
            # Confirm deletion
            confirm = self._get_validated_input(
                f"Are you sure you want to delete password for {username} at {website}? (yes/no): ",
                valid_options=['yes', 'no'],
                default='no'
            )
            
            if confirm != 'yes':
                print("Deletion cancelled.")
                self.logger.info(f"Password deletion cancelled for {username} at {website}")
                return False
                
            # Save the updated list
            encrypted_data = self.fernet.encrypt(json.dumps(passwords).encode())
            with open(self.passwords_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.logger.info(f"Deleted password for {username} at {website}")
            print(f"✅ Deleted password for {username} at {website}")
            return True
        else:
            self.logger.warning(f"Attempted to delete non-existent password for {username} at {website}")
            print(f"No matching entry found for {username} at {website}")
            return False
    
    def backup_passwords(self, backup_path=None):
        """Create a backup of the encrypted password file"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to create backups.")
            return False
            
        self.update_activity_time()
            
        if not os.path.exists(self.passwords_file):
            print("No password file to backup.")
            return False
        
        if backup_path is None:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            backup_path = os.path.join(
                self.data_dir, f"passwords_backup_{timestamp}.enc")
        
        try:
            # Copy the encrypted file
            with open(self.passwords_file, 'rb') as src:
                with open(backup_path, 'wb') as dest:
                    dest.write(src.read())
            
            self.logger.info(f"Backup created at: {backup_path}")
            print(f"✅ Backup created at: {backup_path}")
            return True
        except Exception as e:
            error_msg = f"Error creating backup: {e}"
            self.logger.error(error_msg)
            print(f"❌ {error_msg}")
            return False

    def _get_validated_input(self, prompt, valid_options=None, valid_pattern=None, default=None, allow_back=True):
        """Get user input with validation"""
        # Add back option notice if allowed
        if allow_back:
            if prompt.strip().endswith(':'):
                prompt = prompt.strip() + " (or 'b' to go back): "
            else:
                prompt = prompt.strip() + " (or enter 'b' to go back): "
                
        while True:
            user_input = input(prompt)
            
            # Check for back command
            if allow_back and user_input.lower() in ['b', 'back']:
                return '_BACK_'
                
            # Use default if input is empty and default is provided
            if not user_input and default is not None:
                return default
                
            # Validate against valid options
            if valid_options and user_input.lower() not in valid_options:
                print(f"⚠️ Invalid input. Valid options are: {', '.join(valid_options)}")
                continue
                
            # Validate against pattern
            if valid_pattern and not re.match(valid_pattern, user_input):
                print(f"⚠️ Invalid input. Must match pattern: {valid_pattern}")
                continue
            
            # Log input (but not passwords or sensitive data)
            if self.session_authenticated and not any(s in prompt.lower() for s in ["password", "secret", "master"]):
                self.logger.debug(f"User input: {prompt.split(':')[0]} = {user_input}")
                
            return user_input.lower() if valid_options else user_input

    def _get_validated_int(self, prompt, min_value=None, max_value=None, default=None, allow_back=True):
        """Get integer input with validation"""
        # Add back option notice
        if allow_back:
            if prompt.strip().endswith(':'):
                prompt = prompt.strip() + " (or 'b' to go back): "
            else:
                prompt = prompt.strip() + " (or enter 'b' to go back): "
                
        while True:
            user_input = input(prompt)
            
            # Check for back command
            if allow_back and user_input.lower() in ['b', 'back']:
                return '_BACK_'
                
            # Use default if input is empty and default is provided
            if not user_input and default is not None:
                return default
                
            # Validate that input is an integer
            try:
                value = int(user_input)
            except ValueError:
                print("⚠️ Please enter a valid number.")
                continue
                
            # Validate minimum value
            if min_value is not None and value < min_value:
                print(f"⚠️ Value must be at least {min_value}.")
                continue
                
            # Validate maximum value
            if max_value is not None and value > max_value:
                print(f"⚠️ Value must be no more than {max_value}.")
                continue
                
            return value
    
    def run_interactive_menu(self):
        """Run an interactive menu for the password manager"""
        while True:
            # Check if session is authenticated
            if not self.session_authenticated:
                auth_result = self.authenticate_master_account()
                if not auth_result:
                    print("Exiting Password Manager due to authentication failure.")
                    break
                continue  # Show menu after successful authentication
            
            # Update activity time
            self.update_activity_time()
            
            # Show the main menu
            print("\n=== Password Manager ===")
            print(f"Logged in as: {self.username}")
            print("1. Generate a new password")
            print("2. Save a password")
            print("3. Find passwords")
            print("4. List all websites")
            print("5. Delete a password")
            print("6. Create backup")
            print("7. Show storage location")
            print("8. Logout")
            print("9. Exit")
            
            choice = self._get_validated_input(
                "\nChoose an option (1-9): ", 
                valid_options=['1', '2', '3', '4', '5', '6', '7', '8', '9'],
                allow_back=False  # Can't go back from main menu
            )
            
            # Log menu choice
            self.logger.debug(f"Menu option selected: {choice}")
            
            if choice == '1':
                self._handle_generate_password()
            elif choice == '2':
                self._handle_save_password()
            elif choice == '3':
                self._handle_find_password()
            elif choice == '4':
                self._handle_list_websites()
            elif choice == '5':
                self._handle_delete_password()
            elif choice == '6':
                self.backup_passwords()
            elif choice == '7':
                self._handle_show_storage()
            elif choice == '8':
                print("Logging out...")
                self.logger.info(f"User {self.username} logged out")
                self.session_authenticated = False
            elif choice == '9':
                print("Exiting Password Manager.")
                self.logger.info(f"User {self.username} exited the application")
                break
    
    def _handle_generate_password(self):
        """Handle password generation flow with back option"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to generate passwords.")
            return
            
        self.update_activity_time()
        
        # Get password length
        length = self._get_validated_int(
            "Password length (recommended 15+): ", 
            min_value=4, 
            default=15
        )
        if length == '_BACK_':
            return
        
        # Get special characters option
        use_special = self._get_validated_input(
            "Include special characters (!@#$%^*)()? (y/n): ", 
            valid_options=['y', 'n'], 
            default='y'
        )
        if use_special == '_BACK_':
            return
        use_special = (use_special == 'y')
        
        # Get uppercase option
        use_uppercase = self._get_validated_input(
            "Include uppercase letters? (y/n): ", 
            valid_options=['y', 'n'], 
            default='y'
        )
        if use_uppercase == '_BACK_':
            return
        use_uppercase = (use_uppercase == 'y')
        
        # Get digits option
        use_digits = self._get_validated_input(
            "Include digits? (y/n): ", 
            valid_options=['y', 'n'], 
            default='y'
        )
        if use_digits == '_BACK_':
            return
        use_digits = (use_digits == 'y')
        
        # Generate password
        pwd_info = self.generate_password(
            length, use_special, use_uppercase, use_digits)
        
        if not pwd_info:  # If generation failed (e.g. session expired)
            return
            
        print(f"\n🔑 Generated password: {pwd_info['password']}")
        print(f"🔒 Strength: {pwd_info['strength']}")
        
        # Get save option
        save_option = self._get_validated_input(
            "Save this password? (y/n): ", 
            valid_options=['y', 'n'], 
            default='n'
        )
        if save_option == '_BACK_':
            return
        
        if save_option == 'y':
            # Get username
            while True:
                username = input("Username (or 'b' to go back): ").strip()
                if username.lower() in ['b', 'back']:
                    return
                if username:
                    break
                print("⚠️ Username cannot be empty.")
            
            # Get website
            while True:
                website = input("Website/Service name (or 'b' to go back): ").strip()
                if website.lower() in ['b', 'back']:
                    return
                if website:
                    break
                print("⚠️ Website/Service name cannot be empty.")
            
            # Get notes
            notes = input("Notes (optional, or 'b' to go back): ")
            if notes.lower() in ['b', 'back']:
                return
            
            # Final confirmation
            confirm = self._get_validated_input(
                f"Confirm saving password for {username} at {website}? (y/n): ", 
                valid_options=['y', 'n'], 
                default='y'
            )
            if confirm == '_BACK_':
                return
            
            if confirm == 'y':
                self.save_password(username, website, pwd_info['password'], notes)
            else:
                print("Password not saved.")
    
    def _handle_save_password(self):
        """Handle save password flow with back option"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to save passwords.")
            return
            
        self.update_activity_time()
        
        # Get username
        while True:
            username = input("Username (or 'b' to go back): ").strip()
            if username.lower() in ['b', 'back']:
                return
            if username:
                break
            print("⚠️ Username cannot be empty.")
        
        # Get website
        while True:
            website = input("Website/Service name (or 'b' to go back): ").strip()
            if website.lower() in ['b', 'back']:
                return
            if website:
                break
            print("⚠️ Website/Service name cannot be empty.")
        
        # Get password
        while True:
            password = getpass.getpass("Password (or 'b' to go back): ")
            if password.lower() in ['b', 'back']:
                return
            if password:
                break
            print("⚠️ Password cannot be empty.")
        
        # Get notes
        notes = input("Notes (optional, or 'b' to go back): ")
        if notes.lower() in ['b', 'back']:
            return
        
        # Final confirmation
        confirm = self._get_validated_input(
            f"Confirm saving password for {username} at {website}? (y/n): ", 
            valid_options=['y', 'n'], 
            default='y'
        )
        if confirm == '_BACK_':
            return
        
        if confirm == 'y':
            self.save_password(username, website, password, notes)
        else:
            print("Password not saved.")
    
    def _handle_find_password(self):
        """Handle find password flow with back option"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to find passwords.")
            return
            
        self.update_activity_time()
        
        # Get search term
        while True:
            search_term = input("Search (username or website, or 'b' to go back): ").strip()
            if search_term.lower() in ['b', 'back']:
                return
            if search_term:
                break
            print("⚠️ Search term cannot be empty.")
        
        results = self.find_password(search_term)
        
        if results:
            print(f"\nFound {len(results)} results:")
            for idx, entry in enumerate(results, 1):
                print(f"{idx}. Website: {entry['website']}, Username: {entry['username']}")
            
            valid_indices = [str(i) for i in range(1, len(results) + 1)]
            show_idx = self._get_validated_input(
                "Show password by number (or Enter to go back): ", 
                valid_options=valid_indices + [''],
                default=''
            )
            
            if show_idx == '_BACK_' or not show_idx:
                return
            
            # Re-authenticate to view password
            if not self.require_auth_for_sensitive_action("Viewing password"):
                return
                
            entry = results[int(show_idx) - 1]
            print(f"\nWebsite: {entry['website']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry.get('notes'):
                print(f"Notes: {entry['notes']}")
            print(f"Created on: {entry['created_at']}")
            
            # Log viewed password (but don't include the actual password)
            self.logger.info(f"Viewed password for {entry['username']} at {entry['website']}")
            
            # Pause before returning to menu
            input("\nPress Enter to continue...")
        else:
            print("No results found.")
    
    def _handle_list_websites(self):
        """Handle list websites flow with back option"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to list websites.")
            return
            
        self.update_activity_time()
        
        websites = self.list_websites()
        if websites:
            print("\nList of saved websites/services:")
            for idx, site in enumerate(websites, 1):
                print(f"{idx}. {site}")
            print(f"\nTotal: {len(websites)} websites")
            
            self.logger.info(f"Listed {len(websites)} websites")
            
            # Pause before returning to menu
            input("\nPress Enter to continue...")
        else:
            print("No saved websites.")
    
    def _handle_delete_password(self):
        """Handle delete password flow with back option"""
        # Validate session
        if not self.session_authenticated:
            print("❌ You must be logged in to delete passwords.")
            return
            
        self.update_activity_time()
        
        # Get username
        while True:
            username = input("Username to delete (or 'b' to go back): ").strip()
            if username.lower() in ['b', 'back']:
                return
            if username:
                break
            print("⚠️ Username cannot be empty.")
        
        # Get website
        while True:
            website = input("Website/Service name (or 'b' to go back): ").strip()
            if website.lower() in ['b', 'back']:
                return
            if website:
                break
            print("⚠️ Website/Service name cannot be empty.")
        
        self.delete_password(username, website)
    
    def _handle_show_storage(self):
        """Handle show storage flow with back option"""
        # Validate session and require re-authentication
        if not self.require_auth_for_sensitive_action("Viewing storage information"):
            return
        
        self.logger.info("Storage information displayed")
        
        print("\nStorage Information:")
        print(f"Data directory: {self.data_dir}")
        print(f"Passwords file: {self.passwords_file}")
        print(f"Salt file: {self.salt_file}")
        print(f"Master username file: {self.username_file}")
        print(f"Master password hash file: {self.password_hash_file}")
        print(f"Login attempts file: {self.login_attempts_file}")
        print(f"Log file: {self.log_file}")
        print(f"Session timeout: {self.session_timeout//60} minutes")
        print(f"Lockout duration: {self.lockout_duration//60} minutes")
        
        if os.path.exists(self.passwords_file):
            size = os.path.getsize(self.passwords_file)
            print(f"Password file size: {size} bytes")
            print(f"Last modified: {time.ctime(os.path.getmtime(self.passwords_file))}")
        
        # Pause before returning to menu
        input("\nPress Enter to continue...")


# Run the program
if __name__ == "__main__":
    print("=== Secure Password Manager ===")
    print("All data is stored locally and encrypted")
    
    try:
        manager = SecurePasswordManager()
        manager.run_interactive_menu()
    except KeyboardInterrupt:
        print("\nProgram interrupted. Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
        # Don't log the error details to console for security reasons
        if hasattr(manager, 'logger'):
            manager.logger.error(f"Unhandled exception: {str(e)}", exc_info=True) 