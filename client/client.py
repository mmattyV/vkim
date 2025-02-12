# client.py

import socket
import struct
import sys
import threading
import os

# For blocking until a server response is received
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from serialization import serialize_custom, deserialize_custom
from operations import Operations
from bcrypt_utils import hash_password  # For hashing passwords with bcrypt

class ChatClient:
    def __init__(self, host='localhost', port=5050):
        self.server_host = host
        self.server_port = port
        self.sock = None
        self.receive_thread = None
        self.running = False
        self.username = None  # Track the logged-in user

        # Event and variable to handle responses to CHECK_USERNAME requests
        self.check_username_event = threading.Event()
        self.account_exists_response = None  # Will be set to an Operations value

    def connect(self):
        """Establish a connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.running = True
            print(f"Connected to server at {self.server_host}:{self.server_port}")

            # Start a thread to listen for incoming messages.
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            sys.exit(1)

    def send_message(self, message_type: Operations, payload: list):
        """Serialize and send a message to the server."""
        try:
            serialized = serialize_custom(message_type, payload)
            self.sock.sendall(serialized)
            print(f"Sent {message_type.name} with payload: {payload}")
        except Exception as e:
            print(f"Failed to send message: {e}")

    def recvall(self, n):
        """Helper function to receive n bytes or return what is received if EOF is hit."""
        data = b''
        while len(data) < n:
            try:
                packet = self.sock.recv(n - len(data))
                if not packet:
                    return data
                data += packet
            except Exception:
                return data
        return data

    def receive_messages(self):
        """Continuously listen for messages from the server."""
        while self.running:
            try:
                # First, receive the fixed part of the message (msg_type and payload_length)
                header = self.recvall(8)
                if not header:
                    print("Server closed the connection.")
                    self.running = False
                    break

                msg_type, payload_length = struct.unpack("!I I", header)

                print('\nReceived header:', header)
                print('Payload length:', payload_length)

                # Now receive the payload.
                payload_bytes = self.recvall(payload_length)
                if len(payload_bytes) != payload_length:
                    print("Incomplete payload received.")
                    continue

                # Deserialize the full message (header + payload)
                msg_type_received, payload_received = deserialize_custom(header + payload_bytes)
                self.handle_server_response(msg_type_received, payload_received)
            except Exception as e:
                print(f"Error receiving message: {e}")
                self.running = False
                break

    def handle_server_response(self, msg_type, payload):
        """Handle and display the server's response."""
        try:
            operation = Operations(msg_type)
            if operation == Operations.RECEIVE_CURRENT_MESSAGE:
                # Display the incoming message.
                print(f"\n[New Message]: {payload[0]}")
            else:
                print(f"Server Response: {operation.name}, Payload: {payload}\n")
                # If the response is for a username check, signal the waiting thread.
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    self.account_exists_response = operation
                    self.check_username_event.set()
                elif operation == Operations.SUCCESS and "Auth successful" in payload:
                    self.username = payload[0]
        except ValueError:
            print(f"Unknown message type received: {msg_type}, Payload: {payload}")

    def create_account(self, username):
        """Prompt for a new password and send account creation."""
        # This method is called only after the server has indicated that the account does not exist.
        password = input("Enter new password: ").strip()
        if not password:
            print("Password cannot be empty.")
            return
        # Hash the password using bcrypt.
        hashed_password = hash_password(password)
        # Send the CREATE_ACCOUNT request.
        self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password.decode('utf-8')])
    
    def try_create_account(self):
        """Check whether a username exists and then prompt for account creation if it doesn't."""
        username = input("Enter username (to see if it exists): ").strip()
        if not username:
            print("Username cannot be empty.")
            return
        # Send the CHECK_USERNAME request.
        self.send_message(Operations.CHECK_USERNAME, [username])
        # Clear the event and wait for the server's response.
        self.check_username_event.clear()
        print("Waiting for server response...", flush=True)
        # Wait (blocking) until the event is set (or timeout after, say, 10 seconds)
        if self.check_username_event.wait(timeout=10):
            # Now check the response.
            if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                # Proceed with account creation.
                self.create_account(username)
            elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                print("Account already exists. Please log in.")
                self.log_in()
            else:
                print("Unexpected response received.")
        else:
            print("No response from server. Please try again later.")

    def log_in(self):
        """Handle user login."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        if not username or not password:
            print("Username and password cannot be empty.")
            return
        self.send_message(Operations.LOGIN, [username, password])

    def send_chat_message(self):
        """Handle sending a chat message."""
        if not self.username:
            print("You must be logged in to send messages.")
            return
        recipient = input("Enter recipient username: ").strip()
        message = input("Enter message: ").strip()
        if not recipient or not message:
            print("Recipient and message cannot be empty.")
            return
        self.send_message(Operations.SEND_MESSAGE, [recipient, message])

    def logout(self):
        """Handle user logout."""
        if not self.username:
            print("You are not logged in.")
            return
        self.send_message(Operations.LOGOUT, [self.username])
        self.username = None

    def close(self):
        """Close the connection to the server."""
        self.running = False
        if self.sock:
            self.sock.close()
            print("Disconnected from server.")

    def run(self):
        """Run the client interface."""
        self.connect()
        try:
            while self.running:
                # Print the main menu.
                print("\nChoose an operation:")
                print("1. Create Account")
                print("2. Log In")
                print("3. Send Message")
                print("4. Logout")
                print("5. Exit")
                # Flush to ensure the prompt is printed immediately.
                sys.stdout.flush()
                choice = input("Enter choice number: ").strip()

                if choice == '1':
                    self.try_create_account()
                elif choice == '2':
                    self.log_in()
                elif choice == '3':
                    self.send_chat_message()
                elif choice == '4':
                    self.logout()
                elif choice == '5':
                    self.close()
                    break
                else:
                    print("Invalid choice. Please try again.")
        except KeyboardInterrupt:
            print("\nInterrupted by user.")
            self.close()

if __name__ == "__main__":
    # Set up connection parameters.
    PORT = 5050  # Port to connect to.
    SERVER_HOST_NAME = socket.gethostname()  # Host name of the machine.
    SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)  # IPv4 address of the machine.

    client = ChatClient(host=SERVER_HOST, port=PORT)
    client.run()
