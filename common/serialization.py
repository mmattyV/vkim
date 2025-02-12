import struct

def serialize_custom(message_type: str, payload: list) -> bytes:
    """Serialize a message into a custom binary format."""
    if message_type not in MESSAGE_TYPES:
        raise ValueError("Invalid message type")
    
    msg_type = MESSAGE_TYPES[message_type]
    payload_bytes = b"".join(s.encode("utf-8") + b"\x00" for s in payload)  # Null-terminated strings
    payload_length = len(payload_bytes)
    
    return struct.pack(f"!I I {payload_length}s", msg_type, payload_length, payload_bytes)

def deserialize_custom(data: bytes):
    """Deserialize a custom binary message."""
    msg_type, payload_length = struct.unpack("!I I", data[:8])
    payload_bytes = data[8:]
    
    if len(payload_bytes) != payload_length:
        raise ValueError("Payload length mismatch")
    
    payload = payload_bytes.decode("utf-8").split("\x00")[:-1]  # Split and remove trailing empty entry
    
    return msg_type, payload

# Example Usage
serialized = serialize_custom("SEND_MESSAGE", ["user1", "user2", "Hello"])
print(f"Serialized: {serialized}")

msg_type, payload = deserialize_custom(serialized)
print(f"Deserialized: {msg_type}, {payload}")