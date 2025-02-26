import unittest
import struct
import sys
import os 

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from operations import Operations
from serialization import serialize_custom, deserialize_custom

class TestSerialization(unittest.TestCase):
    
    def test_serialize_custom_valid(self):
        """Test serialization with a valid message type and payload."""
        payload = ["user1", "user2", "Hello"]
        serialized = serialize_custom(Operations.CREATE_ACCOUNT, payload)
        
        msg_type, payload_length = struct.unpack("!I I", serialized[:8])
        payload_bytes = serialized[8:]
        
        self.assertEqual(msg_type, Operations.CREATE_ACCOUNT.value)
        self.assertEqual(payload_length, len(payload_bytes))
        self.assertEqual(payload_bytes.decode("utf-8").split("\x00")[:-1], payload)
    
    def test_serialize_invalid_message_type(self):
        """Test serialization with an invalid message type."""
        with self.assertRaises(ValueError):
            serialize_custom(99, ["test"])  # 99 is not a valid Operations enum value

    def test_serialize_empty_payload(self):
        """Test serialization with an empty payload."""
        serialized = serialize_custom(Operations.LOGIN, [])
        msg_type, payload_length = struct.unpack("!I I", serialized[:8])
        
        self.assertEqual(msg_type, Operations.LOGIN.value)
        self.assertEqual(payload_length, 0)
        self.assertEqual(serialized[8:], b"")
    
    def test_deserialize_custom_valid(self):
        """Test deserialization with a valid serialized message."""
        payload = ["user1", "message"]
        serialized = serialize_custom(Operations.SEND_MESSAGE, payload)
        msg_type, deserialized_payload = deserialize_custom(serialized)
        
        self.assertEqual(msg_type, Operations.SEND_MESSAGE.value)
        self.assertEqual(deserialized_payload, payload)
    
    def test_deserialize_payload_length_mismatch(self):
        """Test deserialization with a payload length mismatch."""
        payload = "Hello".encode("utf-8")
        malformed_data = struct.pack("!I I", Operations.LOGIN.value, len(payload) + 5) + payload
        
        with self.assertRaises(ValueError):
            deserialize_custom(malformed_data)
    
    def test_deserialize_empty_payload(self):
        """Test deserialization of an empty payload."""
        serialized = serialize_custom(Operations.LOGOUT, [])
        msg_type, deserialized_payload = deserialize_custom(serialized)
        
        self.assertEqual(msg_type, Operations.LOGOUT.value)
        self.assertEqual(deserialized_payload, [])

if __name__ == "__main__":
    unittest.main()
