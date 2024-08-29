#!/usr/bin/env python3
"""Encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt.
    Args:
        password: A string containing the password to hash.
    Returns:
        A salted, hashed password, which is a byte string.
    """
    # Convert the password to bytes
    encoded = password.encode()
    # Generate a salt and hash the password
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password.
    Args:
        hashed_password: A byte string of the hashed password.
        password: A string of the password to check.
    Returns:
        True if the password is valid, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
