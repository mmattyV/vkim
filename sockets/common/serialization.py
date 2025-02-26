import struct
from operations import Operations
import json

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

def serialize_json(message_type: Operations, payload: list) -> bytes:
    """
    Serialize a message and its payload into a JSON-based binary format
    that prepends an 8-byte header.

    The JSON object has two keys:
      - "message_type": an integer representing the Operations enum value
      - "payload": a list of strings for the message content

    The JSON string is then encoded into UTF-8 bytes. An 8-byte header is
    prepended to the payload:
      - The first 4 bytes are set to 0 (unused)
      - The next 4 bytes encode the length of the JSON payload

    Args:
        message_type (Operations): The type of message (an Operations enum value)
        payload (list): List of strings to include in the message

    Returns:
        bytes: The complete binary message (header + JSON payload)

    Raises:
        ValueError: If message_type is not a valid Operations enum value

    Example:
        >>> serialize_custom(Operations.LOGIN, ["username", "password"])
        b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x2a{"message_type": 1, "payload": ["username", "password"]}'
    """
    if not isinstance(message_type, Operations):
        raise ValueError(f"Invalid message type: {message_type}")
    
    data = {
        "message_type": message_type.value,
        "payload": payload
    }
    json_string = json.dumps(data)
    json_bytes = json_string.encode("utf-8")
    payload_length = len(json_bytes)
    # Create an 8-byte header: first 4 bytes (unused, set to 0), next 4 bytes = payload length.
    header = struct.pack("!I I", 0, payload_length)
    return header + json_bytes

def deserialize_json(data: bytes):
    """
    Deserialize a JSON-based binary message (with an 8-byte header) into its components.

    The function expects:
      - An 8-byte header (first 4 bytes unused, next 4 bytes indicating the length
        of the JSON payload)
      - Followed by a JSON-encoded bytes object that, when decoded, must contain:
          - "message_type": an integer corresponding to an Operations enum value
          - "payload": a list of strings

    Args:
        data (bytes): The complete binary data (header + JSON payload)

    Returns:
        tuple: A tuple (message_type: int, payload: list)

    Raises:
        ValueError: If the data is too short, the payload length does not match, or
                    if required keys are missing in the JSON object.
        UnicodeDecodeError: If the JSON payload is not valid UTF-8.
    """
    if len(data) < 8:
        raise ValueError("Data too short to contain header")
    
    header = data[:8]
    json_bytes = data[8:]
    # Unpack header: first 4 bytes are unused, second 4 bytes indicate payload length.
    _, payload_length = struct.unpack("!I I", header)
    if len(json_bytes) != payload_length:
        raise ValueError("Payload length mismatch")
    
    json_string = json_bytes.decode("utf-8")
    data_dict = json.loads(json_string)
    
    if "message_type" not in data_dict or "payload" not in data_dict:
        raise ValueError("Deserialized JSON does not contain required keys")
    
    return data_dict["message_type"], data_dict["payload"]