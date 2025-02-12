import socket
import struct
import sys
import threading
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from serialization import serialize_custom, deserialize_custom
from operations import Operations

class ChatClient:
    def __init__(self, host='localhost', port=12345):
        self.server_host = host
        self.server_port = port
        self.sock = None
        self.receive_thread = None
        self.running = False

    def connect(self):
        """Establish a connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.running = True
            print(f"Connected to server at {self.server_host}:{self.server_port}")
            
            # Start a thread to listen for incoming messages
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

    def receive_messages(self):
        """Continuously listen for messages from the server."""
        while self.running:
            try:
                # First, receive the fixed part of the message (msg_type and payload_length)
                header = self.sock.recv(8)
                if not header:
                    print("Server closed the connection.")
                    self.running = False
                    break

                msg_type, payload_length = struct.unpack("!I I", header)
                # Now receive the payload
                payload_bytes = b""
                while len(payload_bytes) < payload_length:
                    chunk = self.sock.recv(payload_length - len(payload_bytes))
                    if not chunk:
                        break
                    payload_bytes += chunk

                if len(payload_bytes) != payload_length:
                    print("Incomplete payload received.")
                    continue

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
            print(f"Server Response: {operation.name}, Payload: {payload}")
        except ValueError:
            print(f"Unknown message type received: {msg_type}, Payload: {payload}")

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
                print("\nChoose an operation:")
                print("1. Create Account")
                print("2. Log In")
                print("3. Send Message")
                print("4. Logout")
                print("5. Exit")
                choice = input("Enter choice number: ").strip()

                if choice == '1':
                    self.create_account()
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

    def create_account(self):
        """Handle account creation."""
        username = input("Enter new username: ").strip()
        password = input("Enter password: ").strip()
        self.send_message(Operations.CREATE_ACCOUNT, [username, password])

    def log_in(self):
        """Handle user login."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        self.send_message(Operations.LOGIN, [username, password])

    def send_chat_message(self):
        """Handle sending a chat message."""
        recipient = input("Enter recipient username: ").strip()
        message = input("Enter message: ").strip()
        self.send_message(Operations.SEND_MESSAGE, [recipient, message])

    def logout(self):
        """Handle user logout."""
        self.send_message(Operations.LOGOUT, [])

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Chat Client")
    parser.add_argument('--host', type=str, default='localhost', help='Server host')
    parser.add_argument('--port', type=int, default=12345, help='Server port')
    args = parser.parse_args()

    client = ChatClient(host=args.host, port=args.port)
    client.run()