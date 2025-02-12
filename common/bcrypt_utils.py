# bcrypt_utils.py
import bcrypt

def hash_password(plain_password: str) -> bytes:
    """
    Hashes a plaintext password using bcrypt.
    Returns the hashed password as bytes.
    """
    # Generate a salt and hash the password.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed

def verify_password(plain_password: str, hashed_password: bytes) -> bool:
    """
    Verifies that a plaintext password matches the given hashed password.
    Returns True if they match, False otherwise.
    """
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)
