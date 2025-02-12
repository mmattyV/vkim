# server.py

import socket
import struct
import threading
import sys
import os
import fnmatch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from operations import Operations
from user import User
from serialization import deserialize_custom, serialize_custom


class WireServer:
    """
    Initializes the server object with necessary configurations.
    """
    # Configuration Constants
    PORT = 5050  # Port to listen on
    SERVER_HOST_NAME = socket.gethostname()  # Host name of the machine
    SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)  # IPv4 address of the machine
    HEADER = 8  # Fixed header length in bytes for message length
    FORMAT = "utf-8"  # Encoding/decoding format
    DISCONNECT_MESSAGE = "!DISCONNECT"  # Special disconnect message
    ADDR = (SERVER_HOST, PORT)

    # Globals for account management
    USER_LOCK = threading.Lock()
    USERS = {}       # Dictionary to store User objects {username: User}
    ACTIVE_USERS = {}  # Dictionary to store active connections {username: conn}

    # Create the server socket (IPv4, TCP)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)



    def recvall(self, conn, n):
        """Helper function to receive n bytes or return None if EOF is hit."""
        data = b''
        while len(data) < n:
            try:
                packet = conn.recv(n - len(data))
                if not packet:
                    return data
                data += packet
            except:
                return data
        return data

    def handle_client(self, conn, addr):
        """
        Handles an incoming client connection by reading a fixed-length header, then reading the message
        and using our custom deserialization format.
        """
        print(f"[NEW CONNECTION] {addr} connected.")
        connected = True
        current_username = None  # Track the username associated with this connection
        while connected:
            # Read the header to know the message type and payload length.
            header = self.recvall(conn, self.HEADER)
            print(f"Received header: {header}")
            if not header:
                print("Client disconnected before sending data.")
                connected = False
                break

            try:
                # Unpack the header into message type and payload length
                _, payload_length = struct.unpack("!I I", header)
            except struct.error:
                print("Invalid header received. Disconnecting client.")
                connected = False
                break

            # Receive the payload based on the payload_length
            data = self.recvall(conn, payload_length)
            if not data or len(data) != payload_length:
                print("Incomplete payload received. Disconnecting client.")
                connected = False
                break

            # Use custom deserialization
            try:
                msg_type_received, payload_received = deserialize_custom(header + data)
            except ValueError as e:
                print("Deserialization error:", e)
                connected = False
                break  # Disconnect if deserialization fails

            print('Processing operation...')
            # Dispatch based on the numeric message type.
            
            if msg_type_received == Operations.CHECK_USERNAME.value:
                response = self.check_username(payload_received[0])  # Assuming payload[0] is the username.
                self.package_send(response, conn)
            if msg_type_received == Operations.CREATE_ACCOUNT.value:
                # Assume payload[0] is the username.
                response = self.create_account(payload_received[0], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.DELETE_ACCOUNT.value:
                response = self.delete_account(payload_received[0])
                self.package_send(response, conn)
            elif msg_type_received == Operations.LOGIN.value:
                response = self.login(payload_received[0], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.LOGOUT.value:
                response = self.logout(payload_received[0])
                self.package_send(response, conn)
            elif msg_type_received == Operations.LIST_ACCOUNTS.value:
                pattern = payload_received[1] if payload_received else ""
                response = self.list_accounts(pattern)
                self.package_send(response, conn)
            elif msg_type_received == Operations.SEND_MESSAGE.value:
                if payload_received[0] == self.DISCONNECT_MESSAGE:
                    connected = False
                    response = self.payload(Operations.SUCCESS, [""])
                else:
                    # Expect info to be a string with sender, receiver, msg separated by newline.
                    try:
                        sender, receiver, msg = payload_received[0].split("\n")
                    except ValueError:
                        response = self.payload(Operations.FAILURE, ["Invalid message format."])
                        self.package_send(response, conn)
                        continue
                    response = self.send_message(sender, receiver, msg)
                    # If the recipient is active, deliver immediately.
                    if receiver in self.ACTIVE_USERS:
                        msg_data = self.deliver_msgs_immediately(msg)
                        self.package_send(msg_data, self.ACTIVE_USERS[receiver])
                self.package_send(response, conn)
            elif msg_type_received == Operations.DELETE_MESSAGE.value:
                # Expected payload: [username, delete_info]
                response = self.delete_message(payload_received[0], payload_received[1])
                self.package_send(response, conn)

            elif msg_type_received == Operations.VIEW_UNDELIVERED_MESSAGES.value:
                # Expect the payload to include the username and the count of messages requested.
                # For example, payload_received might be: [username, "5"]
                username = payload_received[0]
                try:
                    count = int(payload_received[1])
                except (IndexError, ValueError):
                    count = 10  # default value if not specified or invalid
                response = self.view_msgs(username, count)
                self.package_send(response, conn)

        # Remove the connection from ACTIVE_USERS if present.
        for key, value in list(self.ACTIVE_USERS.items()):
            if value == conn:
                del self.ACTIVE_USERS[key]
                break
        conn.close()
        
    def payload(self, operation, info):
        """
        Create a response payload as a dictionary.
        'operation' should be an Operations enum member,
        and 'info' should be a string (or empty string if not applicable).
        """
        return {"operation": operation, "info": info}

    def calculate_send_length(self, serialized_data):
        """
        Calculates and returns a fixed-length bytes object representing the length of the serialized data.
        """
        message_length = len(serialized_data)
        send_length = str(message_length).encode(self.FORMAT)
        send_length += b" " * (self.HEADER - len(send_length))
        return send_length

    def package_send(self, data, conn):
        """
        Serializes the payload using the custom format and sends it with a fixed-length header.
        'data' here is expected to be a tuple or a list that can be passed to serialize_custom.
        For example, if 'data' is a payload for a response, call:
            serialize_custom(response_operation, response_payload_list)
        """
        # For example, assume 'data' is already in the form: (operation, [list of response strings])
        print("data is:", data)
        response_bytes = serialize_custom(data['operation'], data['info'])
        conn.send(response_bytes)

    def start_server(self):
        """
        Starts the server and listens for incoming connections.
        For every new connection, a new thread is created to handle it.
        """
        print(f"[STARTING] Server is starting at {self.SERVER_HOST} on port {self.PORT}...")
        self.server.listen()
        print(f"[LISTENING] Server is listening on {self.SERVER_HOST}")
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
            
    def check_username(self, username):
        """
        Checks if a username already exists.
        
        If the username exists, returns a payload indicating that the account exists so that
        the client can prompt the user to log in. Otherwise, returns a payload indicating that the
        username is available for account creation, so the client should prompt the user to supply a password.
        
        Returns:
            dict: A payload with an operation code and an info message.
        """
        with self.USER_LOCK:
            if username in self.USERS:
                # The account already exists; prompt the client for a password (login).
                return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, [""])
            else:
                # The account does not exist; prompt the client to create a new account by supplying a password.
                return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, [""])
            
    def create_account(self, username, conn):
        with self.USER_LOCK:
            if username in self.USERS:
                return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, [""])
            new_user = User(username)
            self.USERS[username] = new_user
            self.ACTIVE_USERS[username] = conn
            user_obj = self.USERS[username]
            unread_count = user_obj.undelivered_messages.qsize()
        return self.payload(Operations.SUCCESS, [username, "Auth successful", f"{unread_count}"])

    def login(self, username, conn):
        with self.USER_LOCK:
            if username in self.USERS:
                self.ACTIVE_USERS[username] = conn
                user_obj = self.USERS[username]
                unread_count = user_obj.undelivered_messages.qsize()
                # Return the username along with a success message and the unread count.
                return self.payload(
                    Operations.SUCCESS, 
                    [username, "Auth successful", f"{unread_count}"]
                )
        return self.payload(Operations.FAILURE, ["Auth unsuccessful"])

    def logout(self, username):
        with self.USER_LOCK:
            if username in self.ACTIVE_USERS:
                del self.ACTIVE_USERS[username]
                return self.payload(Operations.SUCCESS, ["Logout successful"])
        return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, ["Logout failed"])
    
    def list_accounts(self, pattern=""):
        with self.USER_LOCK:
            # If pattern is empty, match all accounts
            if not pattern:
                matching_accounts = list(self.USERS.keys())
            else:
                matching_accounts = fnmatch.filter(self.USERS.keys(), pattern)
        if not matching_accounts:
            return self.payload(Operations.FAILURE, [f"No accounts match pattern '{pattern}'"])
        accounts_str = "\n".join(matching_accounts)
        return self.payload(Operations.SUCCESS, [accounts_str, "Accounts successfully retrieved"])

    def send_message(self, sender, receiver, msg):
        with self.USER_LOCK:
            if receiver not in self.USERS:
                return self.payload(Operations.FAILURE, ["Receiver does not exist."])
            full_message = f"From {sender}: {msg}"
            # Record the message in the recipient's full history.
            self.USERS[receiver].all_messages.append(full_message)
            if receiver in self.ACTIVE_USERS:
                # If the receiver is active, the message is delivered immediately
                # (handled in handle_client by sending an immediate payload).
                return self.payload(Operations.SUCCESS, ["Message delivered immediately."])
            else:
                # Otherwise, queue the message for later.
                self.USERS[receiver].queue_message(full_message)
                return self.payload(Operations.SUCCESS, ["Message queued for later delivery."])

    def deliver_msgs_immediately(self, msg):
        """
        Prepares a payload for immediate message delivery.
        """
        return self.payload(Operations.RECEIVE_CURRENT_MESSAGE, [msg])

    def view_msgs(self, username, count):
        """
        Retrieves up to 'count' undelivered messages for the given username.
        Once retrieved, these messages are removed from the user's undelivered messages queue.
        Returns a payload with the messages as a newline-separated string.
        """
        with self.USER_LOCK:
            if username not in self.USERS:
                return self.payload(Operations.FAILURE, ["User does not exist."])
            user_obj = self.USERS[username]
            if user_obj.undelivered_messages.empty():
                return self.payload(Operations.FAILURE, ["No undelivered messages."])
            
            messages = []
            for _ in range(count):
                if user_obj.undelivered_messages.empty():
                    break
                messages.append(user_obj.undelivered_messages.get())
        
        if messages:
            joined_messages = "\n".join(messages)
            return self.payload(Operations.SUCCESS, [joined_messages, f"{len(messages)} messages delivered."])
        else:
            return self.payload(Operations.FAILURE, ["No undelivered messages."])
    
    def delete_account(self, username):
        with self.USER_LOCK:
            if username not in self.USERS:
                return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, ["Account does not exist."])
            user_obj = self.USERS[username]
            if not user_obj.undelivered_messages.empty():
                return self.payload(Operations.FAILURE, ["Cannot delete account with unread messages."])
            # Delete from both USERS and ACTIVE_USERS if present.
            del self.USERS[username]
            if username in self.ACTIVE_USERS:
                del self.ACTIVE_USERS[username]
        return self.payload(Operations.SUCCESS, ["Account deleted successfully."])


    def delete_message(self, username, delete_info):
        """
        Deletes messages from a user's message history (both delivered and undelivered).
        
        If delete_info is "ALL", clears the entire message history.
        Otherwise, if delete_info is a numeric string, deletes that many messages from the beginning.
        """
        with self.USER_LOCK:
            if username not in self.USERS:
                return self.payload(Operations.FAILURE, ["User does not exist."])
            user_obj = self.USERS[username]
            deleted_count = user_obj.delete_messages(delete_info)
            if deleted_count == 0:
                return self.payload(Operations.FAILURE, ["No messages deleted."])
            return self.payload(Operations.SUCCESS, [f"Deleted {deleted_count} messages."])


if __name__ == "__main__":
    ws = WireServer()
    ws.start_server()