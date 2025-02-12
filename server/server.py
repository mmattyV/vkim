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
    A multi-threaded chat server that handles multiple client connections and manages user accounts.

    This server implements a custom wire protocol for client-server communication,
    managing user accounts, message delivery, and connection states. It supports
    multiple concurrent client connections using thread-per-client architecture.

    Attributes:
        PORT (int): Port number the server listens on (default: 5050)
        SERVER_HOST_NAME (str): Machine's hostname
        SERVER_HOST (str): Machine's IPv4 address
        HEADER (int): Fixed header length in bytes for message length (8 bytes)
        FORMAT (str): String encoding format (UTF-8)
        DISCONNECT_MESSAGE (str): Special message to indicate client disconnect
        ADDR (tuple): Tuple of (host, port) for socket binding
        USER_LOCK (threading.Lock): Thread-safe lock for user data access
        USERS (dict): Dictionary mapping usernames to User objects
        ACTIVE_USERS (dict): Dictionary mapping usernames to active socket connections
        server (socket.socket): Main server socket for accepting connections

    Thread Safety:
        All methods that access shared user data are protected by USER_LOCK
        to ensure thread-safe operation in multi-client scenarios.
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
        """
        Helper function to receive n bytes or return None if EOF is hit.
        
        Args:
            conn (socket.socket): The socket connection to receive from
            n (int): Number of bytes to receive

        Returns:
            bytes: The received data, may be less than n bytes if connection closed/errored

        Note:
            This method handles partial receives and connection errors gracefully,
            returning whatever data was successfully received.
        """
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
        Handle an individual client connection in a dedicated thread.
        Manages the client connection lifecycle, including message reception,
        deserialization, and dispatching to appropriate handlers. Maintains
        connection state and handles disconnection cleanup.

        Args:
            conn (socket.socket): Socket connection to the client
            addr (tuple): Client address tuple (host, port)

        Thread Safety:
            This method runs in its own thread and uses USER_LOCK when
            accessing shared user data.

        Note:
            Automatically removes client from ACTIVE_USERS on disconnection
        """
        print(f"[NEW CONNECTION] {addr} connected.")
        connected = True
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
            elif msg_type_received == Operations.CREATE_ACCOUNT.value:
                # Expect payload: [username, hashed_password]
                response = self.create_account(payload_received[0], payload_received[1], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.LOGIN.value:
                response = self.login(payload_received[0], payload_received[1], conn)
                self.package_send(response, conn)
            elif msg_type_received == Operations.DELETE_ACCOUNT.value:
                response = self.delete_account(payload_received[0])
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
                        msg_data = self.deliver_msgs_immediately(msg, sender)
                        self.package_send(msg_data, self.ACTIVE_USERS[receiver])
                self.package_send(response, conn)
            elif msg_type_received == Operations.DELETE_MESSAGE.value:
                # Expected payload: [username, delete_info]
                response = self.delete_message(payload_received[0], payload_received[1])
                self.package_send(response, conn)

            elif msg_type_received == Operations.VIEW_UNDELIVERED_MESSAGES.value:
                # Expect the payload to include the username and the count of messages requested.
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
        Create a standardized response payload dictionary.

        Args:
            operation (Operations): The operation type for the response
            info (list): List of strings containing response information

        Returns:
            dict: Dictionary with 'operation' and 'info' keys
        """
        return {"operation": operation, "info": info}

    def package_send(self, data, conn):
        """
        Serialize and send a response to a client. Handles the serialization 
        of response data into the wire protocol format and sends it through 
        the provided socket connection. Uses the custom serialization format 
        defined in serialization.py

        Args:
            data (dict): Response data containing 'operation' and 'info'
            conn (socket.socket): Socket connection to send through
        """
        # For example, assume 'data' is already in the form: (operation, [list of response strings])
        print("data is:", data)
        response_bytes = serialize_custom(data['operation'], data['info'])
        conn.send(response_bytes)

    def start_server(self):
        """
        Start the server and begin accepting client connections.

        Creates a new thread for each client connection accepted.
        Continues running indefinitely until interrupted.

        Note:
            Prints status messages about server startup and active connections
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
        
        Args:
            username (str): Username to check

        Returns:
            dict: Response payload containing:
                - Operations.ACCOUNT_ALREADY_EXISTS if username exists
                - Operations.ACCOUNT_DOES_NOT_EXIST if username is available
        """
        with self.USER_LOCK:
            if username in self.USERS:
                # The account already exists; prompt the client for a password (login).
                return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, [""])
            else:
                # The account does not exist; prompt the client to create a new account by supplying a password.
                return self.payload(Operations.ACCOUNT_DOES_NOT_EXIST, [""])
            
    def create_account(self, username, hashed_password, conn):
        """
        Create a new user account.
        Creates a new User object and associates it with the provided connection.
        The password should already be hashed when received.

        Args:
            username (str): Username for the new account
            hashed_password (str): Pre-hashed password
            conn (socket.socket): Client's socket connection

        Returns:
            dict: Response payload containing:
                - Operations.SUCCESS with user info if created
                - Operations.ACCOUNT_ALREADY_EXISTS if username taken

        Thread Safety:
            Protected by USER_LOCK
        """
        with self.USER_LOCK:
            if username in self.USERS:
                return self.payload(Operations.ACCOUNT_ALREADY_EXISTS, [""])
            # Create a new user with the provided hashed password.
            new_user = User(username, password=hashed_password)
            self.USERS[username] = new_user
            self.ACTIVE_USERS[username] = conn
            unread_count = new_user.undelivered_messages.qsize()
        return self.payload(Operations.SUCCESS, [username, "Auth successful", f"{unread_count}"])

    def login(self, username, hashed_password, conn):
        """
        Authenticate a user and establish their session.

        Verifies credentials and marks the user as active if successful.
        Updates the active connections mapping.

        Args:
            username (str): Username attempting to log in
            hashed_password (str): Pre-hashed password to verify
            conn (socket.socket): Client's socket connection

        Returns:
            dict: Response payload containing:
                - Operations.SUCCESS with user info if authenticated
                - Operations.FAILURE if authentication fails

        Thread Safety:
            Protected by USER_LOCK
        """
        with self.USER_LOCK:
            if username in self.USERS:
                user_obj = self.USERS[username]
                # Check if the stored hashed password matches the one provided.
                if user_obj.password == hashed_password:
                    self.ACTIVE_USERS[username] = conn
                    unread_count = user_obj.undelivered_messages.qsize()
                    return self.payload(Operations.SUCCESS, [username, "Auth successful", f"{unread_count}"])
                else:
                    return self.payload(Operations.FAILURE, ["Incorrect password"])
        return self.payload(Operations.FAILURE, ["Account does not exist"])

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
        """
        Send a message from one user to another.

        Handles both immediate delivery (if receiver is active) and
        message queuing (if receiver is offline).

        Args:
            sender (str): Username of the sending user
            receiver (str): Username of the receiving user
            msg (str): The message content

        Returns:
            dict: Response payload indicating delivery status

        Thread Safety:
            Protected by USER_LOCK

        Note:
            Messages to active users are delivered immediately via
            deliver_msgs_immediately()
        """
        with self.USER_LOCK:
            if receiver not in self.USERS:
                return self.payload(Operations.FAILURE, ["Receiver does not exist."])
            full_message = f"From {sender}: {msg}"
            # Record the message in the recipient's full history.
            if receiver in self.ACTIVE_USERS:
                # If the receiver is active, the message is delivered immediately
                # (handled in handle_client by sending an immediate payload).
                self.USERS[receiver].add_read_message(full_message)
                return self.payload(Operations.SUCCESS, ["Message delivered immediately."])
            else:
                # Otherwise, queue the message for later.
                self.USERS[receiver].queue_message(full_message)
                return self.payload(Operations.SUCCESS, ["Message queued for later delivery."])

    def deliver_msgs_immediately(self, msg, sender):
        """
        Prepares a payload for immediate message delivery.
        """
        return self.payload(Operations.RECEIVE_CURRENT_MESSAGE, [msg, sender])

    def view_msgs(self, username, count):
        """
        Retrieve undelivered messages for a user.

        Fetches and marks as delivered up to 'count' messages from
        the user's undelivered message queue.

        Args:
            username (str): Username requesting messages
            count (int): Maximum number of messages to retrieve

        Returns:
            dict: Response payload containing:
                - Operations.SUCCESS with messages if any found
                - Operations.FAILURE if no messages or user doesn't exist

        Thread Safety:
            Protected by USER_LOCK
        """
        with self.USER_LOCK:
            if username not in self.USERS:
                return self.payload(Operations.FAILURE, ["User does not exist."])
            user_obj = self.USERS[username]
            if user_obj.undelivered_messages.empty():
                return self.payload(Operations.FAILURE, ["No undelivered messages."])
            messages_list = user_obj.get_current_messages(count)
        if messages_list:
            messages_str = "\n".join(messages_list)
            return self.payload(Operations.SUCCESS, [messages_str, f"{len(messages_list)} messages delivered."])
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
        Deletes messages from a user's read messages.
        If delete_info is "ALL", clears the entire read_messages list.
        Otherwise, if delete_info is a numeric string, deletes that many messages from the beginning.
        """
        with self.USER_LOCK:
            if username not in self.USERS:
                return self.payload(Operations.FAILURE, ["User does not exist."])
            user_obj = self.USERS[username]
            deleted_count = user_obj.delete_read_messages(delete_info)
            if deleted_count == 0:
                return self.payload(Operations.FAILURE, ["No messages deleted."])
            return self.payload(Operations.SUCCESS, [f"Deleted {deleted_count} messages."])


if __name__ == "__main__":
    ws = WireServer()
    ws.start_server()