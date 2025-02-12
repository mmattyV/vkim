import struct
from operations import Operations

def serialize_custom(message_type: Operations, payload: list) -> bytes:
    """
    Serialize a message and its payload into a custom binary format.

    The binary format consists of:
    - 4 bytes: Message type (unsigned integer)
    - 4 bytes: Payload length (unsigned integer)
    - N bytes: Payload data (null-terminated UTF-8 strings)

    Args:
        message_type (Operations): The type of message being sent (must be an Operations enum value)
        payload (list): List of strings to be included in the message

    Returns:
        bytes: The serialized message in binary format

    Raises:
        ValueError: If message_type is not a valid Operations enum value

    Example:
        >>> serialize_custom(Operations.LOGIN, ["username", "password"])
        b'\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x11username\\x00password\\x00'
    """
    
    if not isinstance(message_type, Operations):
        raise ValueError(f"Invalid message type: {message_type}")
    
    msg_type = Operations(message_type).value
    payload_bytes = b"".join(s.encode("utf-8") + b"\x00" for s in payload)  # Null-terminated strings
    payload_length = len(payload_bytes)
    
    return struct.pack(f"!I I {payload_length}s", msg_type, payload_length, payload_bytes)

def deserialize_custom(data: bytes):
    """
    Deserialize a binary message into its components.

    Extracts the message type and payload from a binary message that was created
    using serialize_custom(). Handles the custom format where strings in the payload
    are null-terminated.

    Args:
        data (bytes): The binary data to deserialize (must include header and payload)

    Returns:
        tuple: A tuple containing (message_type: int, payload: list)
            - message_type is an integer corresponding to an Operations enum value
            - payload is a list of strings extracted from the message

    Raises:
        ValueError: If the payload length in the header doesn't match the actual payload length
        UnicodeDecodeError: If the payload contains invalid UTF-8 data

    Example:
        >>> data = serialize_custom(Operations.LOGIN, ["username", "password"])
        >>> deserialize_custom(data)
        (1, ["username", "password"])
    """
    
    msg_type, payload_length = struct.unpack("!I I", data[:8])
    payload_bytes = data[8:]
    
    if len(payload_bytes) != payload_length:
        raise ValueError("Payload length mismatch")
    
    payload = payload_bytes.decode("utf-8").split("\x00")[:-1]  # Split and remove trailing empty entry
    
    return msg_type, payload