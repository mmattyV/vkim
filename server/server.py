# server.py

import socket
import threading
import sys
import os

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

    def handle_client(self, conn, addr):
        """
        Handles an incoming client connection by reading a fixed-length header, then reading the message
        and using our custom deserialization format.
        """
        print(f"[NEW CONNECTION] {addr} connected.")
        connected = True
        while connected:
            # Read the header to know the length of the incoming message.
            header_data = conn.recv(self.HEADER).decode(self.FORMAT)
            if header_data:
                message_length = int(header_data)
                data = conn.recv(message_length)
                
                # Use custom deserialization
                try:
                    msg_type, payload = deserialize_custom(data)
                except ValueError as e:
                    print("Deserialization error:", e)
                    break  # Optionally disconnect if deserialization fails
                
                # Dispatch based on the numeric message type.
                if msg_type == Operations.CHECK_USERNAME.value:
                    response = self.check_username(payload[0])  # Assuming payload[0] is the username.
                    self.package_send(response, conn)
                elif msg_type == Operations.CREATE_ACCOUNT.value:
                    # Assume payload[0] is the username.
                    response = self.create_account(payload[0], conn)
                    self.package_send(response, conn)
                elif msg_type == Operations.LOGIN.value:
                    response = self.login(payload[0], conn)
                    self.package_send(response, conn)
                elif msg_type == Operations.LOGOUT.value:
                    response = self.logout(payload[0])
                    self.package_send(response, conn)
                # You can add additional dispatch cases for other operations.
                
                # Optionally, check for a disconnect condition based on the payload.
                if payload and payload[0] == self.DISCONNECT_MESSAGE:
                    connected = False
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")
        
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
        response_bytes = serialize_custom(data[0], data[1])
        send_length = self.calculate_send_length(response_bytes)
        conn.send(send_length)
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
            
    def create_account(self, username, conn):
        with self.USER_LOCK:
            if username in self.USERS:
                return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, "Account already exists")
            new_user = User(username)
            self.USERS[username] = new_user
            self.ACTIVE_USERS[username] = conn
        return self.payload(Operations.SUCCESS, "Account created successfully")
    
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
                return self.payload(
                    Operations.ACCOUNT_ALREADY_EXISTS,
                    "Account exists. Please supply your password to log in."
                )
            else:
                # The account does not exist; prompt the client to create a new account by supplying a password.
                return self.payload(
                    Operations.ACCOUNT_DOES_NOT_EXIST,
                    "No account found. Please supply a password to sign up."
                )

    def login(self, username, conn):
        with self.USER_LOCK:
            if username in self.USERS:
                self.ACTIVE_USERS[username] = conn
                return self.payload(Operations.SUCCESS, "")
        return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, "")

    def logout(self, username):
        with self.USER_LOCK:
            if username in self.ACTIVE_USERS:
                del self.ACTIVE_USERS[username]
                return self.payload(Operations.SUCCESS, "")
        return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, "")


if __name__ == "__main__":
    ws = WireServer()
    ws.start_server()