import unittest
import hashlib
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from hash_utils import hash_password

class TestHashUtils(unittest.TestCase):
    
    def setUp(self):
        self.test_password = "SecurePass123"
        self.fixed_salt = b"MySuperSecretSalt123"

    def test_hash_password_valid(self):
        # Hash the test password
        hashed_password = hash_password(self.test_password)

        # Manually compute expected hash
        sha256 = hashlib.sha256()
        sha256.update(self.fixed_salt + self.test_password.encode('utf-8'))
        expected_hash = sha256.hexdigest()

        # Verify the hash matches the expected output
        self.assertEqual(hashed_password, expected_hash)
        print(f"Hashed password: {hashed_password}")

    def test_hash_password_empty(self):
        # Verify that hashing an empty password raises a ValueError
        with self.assertRaises(ValueError) as context:
            hash_password("")
        
        self.assertEqual(str(context.exception), "Password cannot be empty.")
        print("Empty password correctly raised ValueError")

    def test_hash_password_different_inputs(self):
        # Ensure different passwords produce different hashes
        password1 = "password1"
        password2 = "password2"
        
        hash1 = hash_password(password1)
        hash2 = hash_password(password2)
        
        self.assertNotEqual(hash1, hash2)
        print(f"Different passwords produced different hashes: {hash1} != {hash2}")

    def test_hash_password_consistency(self):
        # Ensure the same password always produces the same hash
        hash1 = hash_password(self.test_password)
        hash2 = hash_password(self.test_password)
        
        self.assertEqual(hash1, hash2)
        print(f"Consistent hashing verified: {hash1} == {hash2}")

if __name__ == '__main__':
    unittest.main()