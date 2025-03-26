#!/usr/bin/env python3
import os
import sys

# Ensure that the project root is in the path so that generated files can be imported.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the generated protobuf message classes.
import message_service_pb2

def compare_grpc_serialization():
    """
    Serialize several gRPC messages and print out the size of the resulting data.
    """
    # 1. LoginRequest: sending username and hashed password.
    login_req = message_service_pb2.LoginRequest(
        username="username",
        hashed_password="hashedpassword"
    )
    login_bytes = login_req.SerializeToString()
    print("LoginRequest serialized size: {} bytes".format(len(login_bytes)))

    # 2. SendMessageRequest: sending sender, recipient, and message content.
    send_msg_req = message_service_pb2.SendMessageRequest(
        sender="alice",
        recipient="bob",
        content="Hello, Bob!"
    )
    send_msg_bytes = send_msg_req.SerializeToString()
    print("SendMessageRequest serialized size: {} bytes".format(len(send_msg_bytes)))

    # 3. ListAccountsRequest: sending username and pattern.
    list_acc_req = message_service_pb2.ListAccountsRequest(
        username="alice",
        pattern="user*"
    )
    list_acc_bytes = list_acc_req.SerializeToString()
    print("ListAccountsRequest serialized size: {} bytes".format(len(list_acc_bytes)))

    # 4. ViewMessagesRequest: sending username and count.
    view_msgs_req = message_service_pb2.ViewMessagesRequest(
        username="alice",
        count=10
    )
    view_msgs_bytes = view_msgs_req.SerializeToString()
    print("ViewMessagesRequest serialized size: {} bytes".format(len(view_msgs_bytes)))

    # 5. DeleteAccount request (using UsernameRequest)
    del_acc_req = message_service_pb2.UsernameRequest(
        username="alice"
    )
    del_acc_bytes = del_acc_req.SerializeToString()
    print("UsernameRequest (for DeleteAccount) serialized size: {} bytes".format(len(del_acc_bytes)))
    print("-" * 60)

def main():
    compare_grpc_serialization()

if __name__ == "__main__":
    main()