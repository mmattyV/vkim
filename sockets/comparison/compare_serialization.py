#!/usr/bin/env python3
import struct
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from operations import Operations
from serialization import serialize_custom, serialize_json

def compare_serialization(operation, payload):
    """
    Serialize the same operation and payload using both the custom protocol and
    the JSON-based protocol. Then print out the size of each resulting message.
    """
    # Serialize with the custom protocol.
    custom_bytes = serialize_custom(operation, payload)
    # Serialize with the JSON protocol.
    json_bytes = serialize_json(operation, payload)
    
    # Print comparison information.
    print("Operation:", operation)
    print("Payload:", payload)
    print("Custom serialization size: {} bytes".format(len(custom_bytes)))
    print("JSON serialization size: {} bytes".format(len(json_bytes)))
    print("-" * 60)

def main():
    # Test cases for several operations.
    # You can add as many cases as you like.

    # 1. Login message
    compare_serialization(Operations.LOGIN, ["username", "password"])
    
    # 2. Send message (note: the protocol expects a single string containing sender, receiver, and message separated by newline)
    compare_serialization(Operations.SEND_MESSAGE, ["alice\nbob\nHello, Bob!"])
    
    # 3. List accounts (for example, sending username and a search pattern)
    compare_serialization(Operations.LIST_ACCOUNTS, ["alice", "user*"])
    
    # 4. View undelivered messages (username and count)
    compare_serialization(Operations.VIEW_UNDELIVERED_MESSAGES, ["alice", "10"])
    
    # 5. Delete account (only username needed)
    compare_serialization(Operations.DELETE_ACCOUNT, ["alice"])
    
    # You can add additional test cases to simulate various payload sizes and message types.

if __name__ == "__main__":
    main()