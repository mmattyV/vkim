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
from hash_utils import hash_password  # For hashing passwords with sha256


class ChatClient:
    def __init__(self, host='localhost', port=5050):
        self.server_host = host
        self.server_port = port
        self.sock = None
        self.receive_thread = None
        self.running = False
        self.username = None  # Track the logged-in user
        self.number_unread_messages = 0  # Track the number of unread messages

        # Events to handle server responses
        self.check_username_event = threading.Event()
        self.account_exists_response = None  # Will be set to an Operations value

        self.login_event = threading.Event()
        self.login_response = None  # Will be set to Operations.SUCCESS or Operations.FAILURE

        self.logout_event = threading.Event()
        self.logout_response = None  # Will be set to Operations.SUCCESS or Operations.FAILURE

        self.create_account_event = threading.Event()
        self.create_account_response = None  # Will be set to Operations.SUCCESS or Operations.FAILURE

        # Event and Response for LIST_ACCOUNTS
        self.list_accounts_event = threading.Event()
        self.list_accounts_response = None  # Will store the server's response

        # Event and Response for SEND_MESSAGE
        self.send_message_event = threading.Event()
        self.send_message_response = None  # Will store the server's response

        # Event and Response for VIEW_UNDELIVERED_MESSAGES
        self.view_msgs_event = threading.Event()
        self.view_msgs_response = None  # Will store the server's response

        # Event and Response for DELETE_MESSAGE
        self.delete_message_event = threading.Event()
        self.delete_message_response = None  # Will store the server's response

        # Event and Response for DELETE_ACCOUNT
        self.delete_account_event = threading.Event()
        self.delete_account_response = None  # Will store the server's response

        # Track the current operation awaiting a response
        self.current_operation = None

        # Lock to synchronize access to current_operation
        self.operation_lock = threading.Lock()

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
                # Display the incoming message immediately
                print(f"\n[New Message from {payload[1]}]: {payload[0]}")
                return  # Return early to avoid processing it as part of current_operation

            # For all other operations, proceed as before
            print(f"Server Response: {operation.name}, Payload: {payload}\n")

            with self.operation_lock:
                current_op = self.current_operation

            if current_op is None:
                print("No operation is currently awaiting a response.")
                return

            if current_op == 'check_username':
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    self.account_exists_response = operation
                    self.check_username_event.set()
                else:
                    print("Unexpected response for CHECK_USERNAME operation.")
                    self.check_username_event.set()  # Unblock to prevent hanging

            elif current_op == 'create_account':
                if operation == Operations.SUCCESS:
                    # Assuming the server sends the username and number of unread messages
                    # For example: [username, "Account created successfully.", "0"]
                    if len(payload) >= 3:
                        self.username = payload[0]
                        try:
                            self.number_unread_messages = int(payload[2])
                        except ValueError:
                            self.number_unread_messages = 0
                    print("Account created successfully. You are now logged in as:", self.username)
                    print("Number of unread messages:", self.number_unread_messages)
                    self.create_account_response = Operations.SUCCESS
                    self.create_account_event.set()
                elif operation == Operations.FAILURE:
                    print("Account creation failed. Please try again.")
                    self.create_account_response = Operations.FAILURE
                    self.create_account_event.set()
                else:
                    print("Unexpected response for CREATE_ACCOUNT operation.")
                    self.create_account_event.set()  # Unblock to prevent hanging

            elif current_op == 'login':
                if operation == Operations.SUCCESS:
                    # Assuming the server sends the username and number of unread messages
                    # For example: [username, "Auth successful", "2"]
                    if len(payload) >= 3:
                        self.username = payload[0]
                        try:
                            self.number_unread_messages = int(payload[2])
                        except ValueError:
                            self.number_unread_messages = 0
                    print("Logged in as:", self.username)
                    print("Number of unread messages:", self.number_unread_messages)
                    self.login_response = Operations.SUCCESS
                    self.login_event.set()
                elif operation == Operations.FAILURE:
                    print("Authentication failed. Please try again.")
                    self.login_response = Operations.FAILURE
                    self.login_event.set()
                else:
                    print("Unexpected response for LOGIN operation.")
                    self.login_event.set()  # Unblock to prevent hanging

            elif current_op == 'logout':
                if operation == Operations.SUCCESS:
                    print("Successfully logged out.")
                    self.logout_response = Operations.SUCCESS
                    self.logout_event.set()
                    self.username = None
                    self.number_unread_messages = 0
                elif operation == Operations.FAILURE:
                    print("Logout failed. Please try again.")
                    self.logout_response = Operations.FAILURE
                    self.logout_event.set()
                else:
                    print("Unexpected response for LOGOUT operation.")
                    self.logout_event.set()  # Unblock to prevent hanging

            elif current_op == 'list_accounts':
                if operation == Operations.SUCCESS:
                    accounts = payload[0]  # Assuming the first payload element is the accounts string
                    print("Accounts:\n" + accounts)
                    self.list_accounts_response = Operations.SUCCESS
                    self.list_accounts_event.set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to retrieve accounts."
                    print(f"Failed to list accounts: {error_message}")
                    self.list_accounts_response = Operations.FAILURE
                    self.list_accounts_event.set()
                else:
                    print("Unexpected response for LIST_ACCOUNTS operation.")
                    self.list_accounts_event.set()  # Unblock to prevent hanging

            elif current_op == 'send_message':
                if operation == Operations.SUCCESS:
                    success_message = payload[0] if payload else "Message sent successfully."
                    print(success_message)
                    self.send_message_response = Operations.SUCCESS
                    self.send_message_event.set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to send message."
                    print(f"Failed to send message: {error_message}")
                    self.send_message_response = Operations.FAILURE
                    self.send_message_event.set()
                else:
                    print("Unexpected response for SEND_MESSAGE operation.")
                    self.send_message_event.set()  # Unblock to prevent hanging

            elif current_op == 'view_msgs':
                if operation == Operations.SUCCESS:
                    messages = payload[0]  # Joined messages as a single string
                    count_info = payload[1]  # e.g., "3 messages delivered."
                    try:
                        message_count = int(count_info.split()[0])
                        self.number_unread_messages -= message_count
                        if self.number_unread_messages < 0:
                            self.number_unread_messages = 0  # Prevent negative counts
                    except (IndexError, ValueError):
                        print("Error parsing message count.")
                    print("Received Messages:")
                    print(messages)
                    print(count_info)
                    print("Number of unread messages:", self.number_unread_messages)
                    self.view_msgs_response = Operations.SUCCESS
                    self.view_msgs_event.set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to retrieve messages."
                    print(f"Failed to retrieve messages: {error_message}")
                    self.view_msgs_response = Operations.FAILURE
                    self.view_msgs_event.set()
                else:
                    print("Unexpected response for VIEW_UNDELIVERED_MESSAGES operation.")
                    self.view_msgs_event.set()  # Unblock to prevent hanging

            elif current_op == 'delete_message':
                if operation == Operations.SUCCESS:
                    success_message = payload[0] if payload else "Messages deleted successfully."
                    print(success_message)
                    self.delete_message_response = Operations.SUCCESS
                    self.delete_message_event.set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to delete messages."
                    print(f"Failed to delete messages: {error_message}")
                    self.delete_message_response = Operations.FAILURE
                    self.delete_message_event.set()
                else:
                    print("Unexpected response for DELETE_MESSAGE operation.")
                    self.delete_message_event.set()  # Unblock to prevent hanging

            elif current_op == 'delete_account':
                if operation == Operations.SUCCESS:
                    success_message = payload[0] if payload else "Account deleted successfully. You have been logged out."
                    print(success_message)
                    self.delete_account_response = Operations.SUCCESS
                    self.delete_account_event.set()
                    # Automatically log out the user
                    self.username = None
                    self.number_unread_messages = 0
                elif operation in (Operations.FAILURE, Operations.ACCOUNT_DOES_NOT_EXIST):
                    error_message = payload[0] if payload else "Failed to delete account."
                    print(f"Failed to delete account: {error_message}")
                    self.delete_account_response = operation
                    self.delete_account_event.set()
                else:
                    print("Unexpected response for DELETE_ACCOUNT operation.")
                    self.delete_account_event.set()  # Unblock to prevent hanging

            # Handle other operations similarly if needed
            else:
                print(f"Unhandled current operation: {current_op}")
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
        # Prepare to wait for create_account response
        with self.operation_lock:
            self.current_operation = 'create_account'
        self.create_account_event.clear()
        # Send the CREATE_ACCOUNT request.
        self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password])
        print("Waiting for account creation response...", flush=True)
        # Wait for the create_account response (with a timeout)
        if self.create_account_event.wait(timeout=10):
            if self.create_account_response == Operations.SUCCESS:
                # Account created successfully
                pass  # Already handled in handle_server_response
            elif self.create_account_response == Operations.FAILURE:
                # Account creation failed
                pass  # Already handled in handle_server_response
            else:
                print("Unexpected account creation response.")
        else:
            print("No response from server. Please try again later.")
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def try_create_account(self):
        """Check whether a username exists and then prompt for account creation if it doesn't."""
        username = input("Enter username (to see if it exists): ").strip()
        if not username:
            print("Username cannot be empty.")
            return
        # Prepare to wait for check_username response
        with self.operation_lock:
            self.current_operation = 'check_username'
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
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def log_in(self):
        """Handle user login."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        if not username or not password:
            print("Username and password cannot be empty.")
            return
        hashed_password = hash_password(password)
        # Prepare to wait for login response
        with self.operation_lock:
            self.current_operation = 'login'
        self.login_event.clear()
        self.send_message(Operations.LOGIN, [username, hashed_password])
        print("Waiting for login response...", flush=True)
        # Wait for the login response (with a timeout)
        if self.login_event.wait(timeout=10):
            if self.login_response == Operations.SUCCESS:
                # Logged in successfully
                pass  # Already handled in handle_server_response
            elif self.login_response == Operations.FAILURE:
                # Failed to log in
                pass  # Already handled in handle_server_response
            else:
                print("Unexpected login response.")
        else:
            print("No response from server. Please try again later.")
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def list_accounts(self):
        """Handle listing of accounts."""
        if not self.username:
            print("You must be logged in to list accounts.")
            return
        pattern = input("Enter a username pattern to search for: ").strip()
        if not pattern:
            pattern = "*"

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'list_accounts'

        # Clear the event and reset the response
        self.list_accounts_event.clear()
        self.list_accounts_response = None

        # Send the LIST_ACCOUNTS request
        self.send_message(Operations.LIST_ACCOUNTS, [self.username, pattern])
        print("Waiting for list accounts response...", flush=True)

        # Wait for the server's response (with a timeout)
        if self.list_accounts_event.wait(timeout=10):
            if self.list_accounts_response == Operations.SUCCESS:
                # The accounts have already been printed in handle_server_response
                pass
            elif self.list_accounts_response == Operations.FAILURE:
                # The error message has already been printed in handle_server_response
                pass
            else:
                print("Unexpected list accounts response.")
        else:
            print("No response from server. Please try again later.")

        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

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

        # Prepare payload as a single string separated by newlines
        payload = "\n".join([self.username, recipient, message])

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'send_message'

        # Clear the event and reset the response
        self.send_message_event.clear()
        self.send_message_response = None

        # Send the SEND_MESSAGE request
        self.send_message(Operations.SEND_MESSAGE, [payload])
        print("Waiting for send message response...", flush=True)

        # Wait for the server's response (with a timeout)
        if self.send_message_event.wait(timeout=10):
            if self.send_message_response == Operations.SUCCESS:
                # Success message already printed in handle_server_response
                pass
            elif self.send_message_response == Operations.FAILURE:
                # Failure message already printed in handle_server_response
                pass
            else:
                print("Unexpected send message response.")
        else:
            print("No response from server. Please try again later.")

        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def view_messages(self):
        """Handle viewing undelivered messages."""
        if not self.username:
            print("You must be logged in to view messages.")
            return

        try:
            count_input = input("Enter the number of messages to retrieve: ").strip()
            if not count_input:
                print("Number of messages cannot be empty.")
                return
            count = int(count_input)
            if count <= 0:
                print("Please enter a positive integer.")
                return
        except ValueError:
            print("Invalid number entered.")
            return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'view_msgs'

        # Clear the event and reset the response
        self.view_msgs_event.clear()
        self.view_msgs_response = None

        # Send the VIEW_UNDELIVERED_MESSAGES request
        self.send_message(Operations.VIEW_UNDELIVERED_MESSAGES, [self.username, str(count)])
        print("Waiting for messages...", flush=True)

        # Wait for the server's response (with a timeout)
        if self.view_msgs_event.wait(timeout=10):
            if self.view_msgs_response == Operations.SUCCESS:
                # Messages already printed in handle_server_response
                pass
            elif self.view_msgs_response == Operations.FAILURE:
                # Error message already printed in handle_server_response
                pass
            else:
                print("Unexpected view messages response.")
        else:
            print("No response from server. Please try again later.")

        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def delete_messages(self):
        """Handle deleting undelivered messages."""
        if not self.username:
            print("You must be logged in to delete messages.")
            return

        delete_info = input("Enter 'ALL' to delete all messages or the number of messages to delete: ").strip()
        if not delete_info:
            print("Delete info cannot be empty.")
            return
        if delete_info.upper() != 'ALL':
            try:
                count = int(delete_info)
                if count <= 0:
                    print("Please enter a positive integer or 'ALL'.")
                    return
            except ValueError:
                print("Invalid input. Enter a positive integer or 'ALL'.")
                return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'delete_message'

        # Clear the event and reset the response
        self.delete_message_event.clear()
        self.delete_message_response = None

        # Send the DELETE_MESSAGE request
        self.send_message(Operations.DELETE_MESSAGE, [self.username, delete_info.upper()])
        print("Waiting for delete message response...", flush=True)

        # Wait for the server's response (with a timeout)
        if self.delete_message_event.wait(timeout=10):
            if self.delete_message_response == Operations.SUCCESS:
                # Success message already printed in handle_server_response
                pass
            elif self.delete_message_response == Operations.FAILURE:
                # Error message already printed in handle_server_response
                pass
            else:
                print("Unexpected delete message response.")
        else:
            print("No response from server. Please try again later.")

        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def delete_account(self):
        """Handle deleting the logged-in user's account."""
        if not self.username:
            print("You must be logged in to delete your account.")
            return

        confirmation = input("Are you sure you want to delete your account? This action cannot be undone. (yes/no): ").strip().lower()
        if confirmation != 'yes':
            print("Account deletion canceled.")
            return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'delete_account'

        # Clear the event and reset the response
        self.delete_account_event.clear()
        self.delete_account_response = None

        # Send the DELETE_ACCOUNT request
        self.send_message(Operations.DELETE_ACCOUNT, [self.username])
        print("Waiting for delete account response...", flush=True)

        # Wait for the server's response (with a timeout)
        if self.delete_account_event.wait(timeout=10):
            if self.delete_account_response == Operations.SUCCESS:
                # Success message already printed in handle_server_response
                pass
            elif self.delete_account_response in (Operations.FAILURE, Operations.ACCOUNT_DOES_NOT_EXIST):
                # Failure message already printed in handle_server_response
                pass
            else:
                print("Unexpected delete account response.")
        else:
            print("No response from server. Please try again later.")

        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def logout(self):
        """Handle user logout."""
        if not self.username:
            print("You are not logged in.")
            return
        # Prepare to wait for logout response
        with self.operation_lock:
            self.current_operation = 'logout'
        self.logout_event.clear()
        self.send_message(Operations.LOGOUT, [self.username])
        print("Waiting for logout response...", flush=True)
        # Wait for the logout response (with a timeout)
        if self.logout_event.wait(timeout=10):
            if self.logout_response == Operations.SUCCESS:
                # Already handled in handle_server_response
                pass
            elif self.logout_response == Operations.FAILURE:
                # Already handled in handle_server_response
                pass
            else:
                print("Unexpected logout response.")
        else:
            print("No response from server. Please try again later.")
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

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
                if self.username is None:
                    # Not logged in: show full menu (create account, log in, exit)
                    print("1. Create Account")
                    print("2. Log In")
                    print("3. Exit")
                else:
                    # Logged in: show options including view messages
                    print("1. List Accounts")
                    print("2. Send Message")
                    print("3. View Messages")
                    print("4. Delete Messages")
                    print("5. Delete Account")
                    print("6. Logout")
                    print("7. Exit")
                sys.stdout.flush()

                choice = input("Enter choice number: ").strip()

                if self.username is None:
                    # Handle choices for when not logged in
                    if choice == '1':
                        self.try_create_account()
                    elif choice == '2':
                        self.log_in()
                    elif choice == '3':
                        self.close()
                        break
                    else:
                        print("Invalid choice. Please try again.")
                else:
                    # Handle choices for when logged in
                    if choice == '1':
                        self.list_accounts()
                    elif choice == '2':
                        self.send_chat_message()
                    elif choice == '3':
                        self.view_messages()
                    elif choice == '4':
                        self.delete_messages()
                    elif choice == '5':
                        self.delete_account()
                    elif choice == '6':
                        self.logout()
                    elif choice == '7':
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