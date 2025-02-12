# server.py

import socket
import struct
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
                msg_type, payload_length = struct.unpack("!I I", header)
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
            if msg_type_received == Operations.CREATE_ACCOUNT.value:
                # Assume payload[0] is the username.
                print('hello 2')
                response = self.create_account(payload_received[0], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.LOGIN.value:
                response = self.login(payload_received[0], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.LOGOUT.value:
                response = self.logout(payload_received[0])
                self.package_send(response, conn)
            
            # Optionally, check for a disconnect condition based on the payload.
            if payload_received and payload_received[0] == self.DISCONNECT_MESSAGE:
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
        print("data is:", data)
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

# server.py

# # server.py

# import socket
# import struct
# import threading
# import sys
# import os

# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

# from operations import Operations
# from user import User
# from serialization import deserialize_custom, serialize_custom


# class WireServer:
#     """
#     Initializes the server object with necessary configurations.
#     """
#     # Configuration Constants
#     PORT = 5050  # Port to listen on
#     SERVER_HOST_NAME = socket.gethostname()  # Host name of the machine
#     SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)  # IPv4 address of the machine
#     HEADER = 8  # Fixed header length in bytes for message type and payload length
#     FORMAT = "utf-8"  # Encoding/decoding format
#     DISCONNECT_MESSAGE = "!DISCONNECT"  # Special disconnect message
#     ADDR = (SERVER_HOST, PORT)

#     # Globals for account management
#     USER_LOCK = threading.Lock()
#     USERS = {}         # Dictionary to store User objects {username: User}
#     ACTIVE_USERS = {}  # Dictionary to store active connections {username: conn}

#     # Create the server socket (IPv4, TCP)
#     server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     server.bind(ADDR)

#     def recvall(self, conn, n):
#         """Helper function to receive n bytes or return None if EOF is hit."""
#         data = b''
#         while len(data) < n:
#             try:
#                 packet = conn.recv(n - len(data))
#                 if not packet:
#                     return data
#                 data += packet
#             except:
#                 return data
#         return data

#     def handle_client(self, conn, addr):
#         """
#         Handles an incoming client connection by reading a fixed-length header, then reading the message
#         and using our custom deserialization format.
#         """
#         print(f"[NEW CONNECTION] {addr} connected.")
#         connected = True
#         current_username = None  # Track the username associated with this connection
#         while connected:
#             # Read the header to know the message type and payload length.
#             header = self.recvall(conn, self.HEADER)
#             print(f"Received header: {header}")
#             if not header:
#                 print("Client disconnected before sending data.")
#                 connected = False
#                 break

#             try:
#                 # Unpack the header into message type and payload length
#                 msg_type, payload_length = struct.unpack("!I I", header)
#             except struct.error:
#                 print("Invalid header received. Disconnecting client.")
#                 connected = False
#                 break

#             # Receive the payload based on the payload_length
#             data = self.recvall(conn, payload_length)
#             if not data or len(data) != payload_length:
#                 print("Incomplete payload received. Disconnecting client.")
#                 connected = False
#                 break

#             # Use custom deserialization
#             try:
#                 msg_type_received, payload_received = deserialize_custom(header + data)
#             except ValueError as e:
#                 print("Deserialization error:", e)
#                 connected = False
#                 break  # Disconnect if deserialization fails

#             print('Processing operation...')
#             # Dispatch based on the numeric message type.
#             if msg_type_received == Operations.CREATE_ACCOUNT.value:
#                 # Expecting payload: [username, password]
#                 if len(payload_received) < 2:
#                     response = self.payload(Operations.FAILURE, ["Insufficient data for account creation"])
#                 else:
                    
#                     response = self.create_account(payload_received[0], payload_received[1], conn)
#                 self.package_send(response, conn)
#             elif msg_type_received == Operations.LOGIN.value:
#                 # Expecting payload: [username, password]
#                 if len(payload_received) < 2:
#                     response = self.payload(Operations.FAILURE, ["Insufficient data for login"])
#                 else:
#                     response = self.login(payload_received[0], payload_received[1], conn)
#                     if response[0] == Operations.SUCCESS:
#                         current_username = payload_received[0]
#                 self.package_send(response, conn)
#             elif msg_type_received == Operations.LOGOUT.value:
#                 # Expecting payload: [username]
#                 if len(payload_received) < 1:
#                     response = self.payload(Operations.FAILURE, ["Insufficient data for logout"])
#                 else:
#                     response = self.logout(payload_received[0])
#                 self.package_send(response, conn)
#             elif msg_type_received == Operations.SEND_MESSAGE.value:
#                 # Expecting payload: [recipient_username, message]
#                 if len(payload_received) < 2:
#                     response = self.payload(Operations.FAILURE, ["Insufficient data for sending message"])
#                 else:
#                     recipient = payload_received[0]
#                     message = payload_received[1]
#                     response = self.send_message(current_username, recipient, message)
#                 self.package_send(response, conn)
#             else:
#                 response = self.payload(Operations.FAILURE, ["Unknown operation"])
#                 self.package_send(response, conn)

#             # Optionally, check for a disconnect condition based on the payload.
#             if payload_received and payload_received[0] == self.DISCONNECT_MESSAGE:
#                 connected = False

#         # Clean up after disconnect
#         if current_username:
#             with self.USER_LOCK:
#                 if current_username in self.ACTIVE_USERS:
#                     del self.ACTIVE_USERS[current_username]
#         conn.close()
#         print(f"[DISCONNECTED] {addr} disconnected.")

#     def payload(self, operation, info):
#         """
#         Create a response payload as a tuple.
#         'operation' should be an Operations enum member,
#         and 'info' should be a list of strings.
#         """
#         return (operation, [info])

#     def calculate_send_length(self, serialized_data):
#         """
#         Calculates and returns a fixed-length bytes object representing the length of the serialized data.
#         """
#         message_length = len(serialized_data)
#         send_length = str(message_length).encode(self.FORMAT)
#         send_length += b" " * (self.HEADER - len(send_length))
#         return send_length

#     def package_send(self, data, conn):
#         """
#         Serializes the payload using the custom format and sends it with a fixed-length header.
#         'data' here is expected to be a tuple: (operation_enum, [list of response strings])
#         """
#         response_bytes = serialize_custom(data[0], data[1])
#         send_length = self.calculate_send_length(response_bytes)
#         conn.send(send_length)
#         conn.send(response_bytes)

#     def start_server(self):
#         """
#         Starts the server and listens for incoming connections.
#         For every new connection, a new thread is created to handle it.
#         """
#         print(f"[STARTING] Server is starting at {self.SERVER_HOST} on port {self.PORT}...")
#         self.server.listen()
#         print(f"[LISTENING] Server is listening on {self.SERVER_HOST}:{self.PORT}")
#         while True:
#             try:
#                 conn, addr = self.server.accept()
#                 thread = threading.Thread(target=self.handle_client, args=(conn, addr))
#                 thread.start()
#                 print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
#             except KeyboardInterrupt:
#                 print("\n[SHUTDOWN] Server is shutting down.")
#                 self.server.close()
#                 break
#             except Exception as e:
#                 print(f"[ERROR] {e}")

#     def create_account(self, username):
#         with self.USER_LOCK:
#             if username in self.USERS:
#                 return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, "Account already exists")
#             new_user = User(username)
#             self.USERS[username] = new_user
#             # Do not add to ACTIVE_USERS yet; login will handle that
#         print(f"[INFO] Account created for user '{username}'.")
#         return self.payload(Operations.SUCCESS, "Account created successfully")

#     def login(self, username, password, conn):
#         with self.USER_LOCK:
#             if username not in self.USERS:
#                 return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, "Username does not exist")
#             user = self.USERS[username]
#             if not user.check_password(password):
#                 return self.payload(Operations.FAILURE, "Incorrect password")
#             if username in self.ACTIVE_USERS and self.ACTIVE_USERS[username]:
#                 return self.payload(Operations.FAILURE, "User already logged in")
#             self.ACTIVE_USERS[username] = conn
#             # Send any undelivered messages
#             if not user.undelivered_messages.empty():
#                 messages = user.get_current_messages()
#                 for msg in messages:
#                     response = self.payload(Operations.RECEIVE_CURRENT_MESSAGE, msg)
#                     self.package_send(response, conn)
#             return self.payload(Operations.SUCCESS, "Login successful")

#     def logout(self, username):
#         with self.USER_LOCK:
#             if username in self.ACTIVE_USERS:
#                 del self.ACTIVE_USERS[username]
#                 print(f"[INFO] User '{username}' logged out.")
#                 return self.payload(Operations.SUCCESS, "Logout successful")
#             else:
#                 return self.payload(Operations.FAILURE, "User not logged in")

#     def send_message(self, sender, recipient, message):
#         with self.USER_LOCK:
#             if not sender:
#                 return self.payload(Operations.FAILURE, "You must be logged in to send messages")
#             if recipient not in self.USERS:
#                 return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, "Recipient does not exist")
#             if recipient in self.ACTIVE_USERS and self.ACTIVE_USERS[recipient]:
#                 recipient_conn = self.ACTIVE_USERS[recipient]
#                 # Serialize and send the message to the recipient
#                 response = self.payload(Operations.RECEIVE_CURRENT_MESSAGE, f"From {sender}: {message}")
#                 self.package_send(response, recipient_conn)
#                 print(f"[MESSAGE] Delivered message from '{sender}' to '{recipient}': {message}")
#             else:
#                 # Store the message for later delivery
#                 self.USERS[recipient].queue_message(f"From {sender}: {message}")
#                 print(f"[MESSAGE] Stored message from '{sender}' to '{recipient}': {message}")
#             return self.payload(Operations.SUCCESS, "Message sent successfully")


# if __name__ == "__main__":
#     ws = WireServer()
#     ws.start_server()