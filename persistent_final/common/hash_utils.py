# hash_utils.py
import hashlib
import base64

# Define a fixed salt (should be the same across all password hashes)
FIXED_SALT = b"MySuperSecretSalt123"  # Keep this secret and do not expose it

def hash_password(plain_password: str) -> str:
    """
    Hashes a plaintext password using SHA-256 with a fixed salt.
    Returns the hashed password as a hexadecimal string.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")

    # Create a SHA-256 hash object
    sha256 = hashlib.sha256()
    # Update the hash object with the fixed salt and password
    sha256.update(FIXED_SALT + plain_password.encode('utf-8'))
    # Get the hexadecimal digest of the hash
    return sha256.hexdigest()