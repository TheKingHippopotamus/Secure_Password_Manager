#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Encryption utilities for the Secure Password Manager"""

import hashlib
import base64
import os
import binascii
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def hash_password(password, salt):
    """
    Create a secure hash of the password using the salt
    
    Args:
        password: The password string
        salt: The salt bytes
        
    Returns:
        Password hash digest
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(salt)
    hash_obj.update(password.encode())
    return hash_obj.digest()

def get_machine_id():
    """
    Get a unique machine identifier, or fallback to a default
    
    Returns:
        String identifier for the current machine
    """
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

def create_system_key(salt):
    """
    Create a system-specific key for encrypting master credentials
    
    Args:
        salt: Salt bytes for key derivation
        
    Returns:
        URL-safe base64 encoded key
    """
    # Use machine-specific information plus salt to create a key
    machine_id = get_machine_id()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(machine_id.encode()))
    return key

def create_user_key(username, password, salt):
    """
    Create an encryption key based on username and password
    
    Args:
        username: The username string
        password: The password string
        salt: Salt bytes for key derivation
        
    Returns:
        Fernet encryption key object
    """
    # Create a combined key using both username and password
    combined_key = username + ":" + password
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(combined_key.encode()))
    return Fernet(key)

def generate_salt():
    """
    Generate a random salt for password hashing
    
    Returns:
        Random salt bytes
    """
    return os.urandom(16) 