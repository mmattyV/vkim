# bcrypt_utils.py
import bcrypt

def hash_password(plain_password: str) -> bytes:
    """
    Hashes a plaintext password using bcrypt.
    Returns the hashed password as bytes.
    """
    # Hash the password.
    # Ensure the fixed salt is correctly formatted
    fixed_salt = b"$2b$12$abcdefghijklmnopqrstuv" 

    # Hash the password using the fixed salt
    hashed = bcrypt.hashpw(plain_password.encode('utf-8'), fixed_salt)

    return hashed
