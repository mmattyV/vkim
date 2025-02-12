# gui_client.py

import socket
import struct
import sys
import threading
import os
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
from functools import partial

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
        self.list_accounts_response = None  # Store the server's response

        # Event and Response for SEND_MESSAGE
        self.send_message_event = threading.Event()
        self.send_message_response = None  # Store the server's response

        # Event and Response for VIEW_UNDELIVERED_MESSAGES
        self.view_msgs_event = threading.Event()
        self.view_msgs_response = None  # Store the server's response

        # Event and Response for DELETE_MESSAGE
        self.delete_message_event = threading.Event()
        self.delete_message_response = None  # Store the server's response

        # Event and Response for DELETE_ACCOUNT
        self.delete_account_event = threading.Event()
        self.delete_account_response = None  # Store the server's response

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
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            sys.exit(1)

    def send_message(self, message_type: Operations, payload: list):
        """Serialize and send a message to the server."""
        try:
            serialized = serialize_custom(message_type, payload)
            self.sock.sendall(serialized)
            print(f"Sent {message_type.name} with payload: {payload}")
        except Exception as e:
            print(f"Failed to send message: {e}")
            messagebox.showerror("Send Error", f"Failed to send message: {e}")

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
                print(f"\n[New Message]: {payload[0]}")
                # Here you can implement a callback or event to update the GUI with the new message
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

    def create_account(self, username, password, gui_callback):
        """Send account creation request."""
        if not password:
            gui_callback("Password cannot be empty.")
            return
        # Hash the password using bcrypt.
        hashed_password = hash_password(password)
        # Prepare to wait for create_account response
        with self.operation_lock:
            self.current_operation = 'create_account'
        self.create_account_event.clear()
        # Send the CREATE_ACCOUNT request.
        self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password.decode('utf-8')])
        print("Waiting for account creation response...", flush=True)
        # Wait for the create_account response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.create_account_event, self.handle_create_account_response, gui_callback), daemon=True).start()

    def handle_create_account_response(self, gui_callback):
        if self.create_account_response == Operations.SUCCESS:
            gui_callback("Account created successfully. You are now logged in.", success=True)
        elif self.create_account_response == Operations.FAILURE:
            gui_callback("Account creation failed. Please try again.", success=False)
        else:
            gui_callback("Unexpected account creation response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def try_create_account(self, username, gui_callback):
        """Check whether a username exists and then prompt for account creation if it doesn't."""
        if not username:
            gui_callback("Username cannot be empty.", success=False)
            return
        # Prepare to wait for check_username response
        with self.operation_lock:
            self.current_operation = 'check_username'
        # Send the CHECK_USERNAME request.
        self.send_message(Operations.CHECK_USERNAME, [username])
        # Clear the event and wait for the server's response.
        self.check_username_event.clear()
        print("Waiting for server response...", flush=True)
        # Wait (non-blocking) until the event is set (or timeout after, say, 10 seconds)
        threading.Thread(target=self.wait_for_event, args=(
            self.check_username_event, self.handle_check_username_response, username, gui_callback), daemon=True).start()

    def handle_check_username_response(self, username, gui_callback):
        if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
            # Proceed with account creation.
            gui_callback("Username available. Please enter a password to create your account.", username=username, create_account=True)
        elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
            gui_callback("Account already exists. Please log in.", success=False)
        else:
            gui_callback("Unexpected response received.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def log_in(self, username, password, gui_callback):
        """Send login request."""
        if not username or not password:
            gui_callback("Username and password cannot be empty.", success=False)
            return
        hashed_password = hash_password(password)
        # Prepare to wait for login response
        with self.operation_lock:
            self.current_operation = 'login'
        self.login_event.clear()
        self.send_message(Operations.LOGIN, [username, hashed_password.decode('utf-8')])
        print("Waiting for login response...", flush=True)
        # Wait for the login response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.login_event, self.handle_login_response, gui_callback), daemon=True).start()

    def handle_login_response(self, gui_callback):
        if self.login_response == Operations.SUCCESS:
            gui_callback("Logged in successfully.", success=True)
        elif self.login_response == Operations.FAILURE:
            gui_callback("Authentication failed. Please try again.", success=False)
        else:
            gui_callback("Unexpected login response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def list_accounts(self, username, pattern, gui_callback):
        """Send list accounts request."""
        if not self.username:
            gui_callback("You must be logged in to list accounts.", success=False)
            return
        pattern = pattern if pattern else "*"

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'list_accounts'

        # Clear the event and reset the response
        self.list_accounts_event.clear()
        self.list_accounts_response = None

        # Send the LIST_ACCOUNTS request
        self.send_message(Operations.LIST_ACCOUNTS, [username, pattern])
        print("Waiting for list accounts response...", flush=True)

        # Wait for the server's response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.list_accounts_event, self.handle_list_accounts_response, gui_callback), daemon=True).start()

    def handle_list_accounts_response(self, gui_callback):
        if self.list_accounts_response == Operations.SUCCESS:
            # The accounts have already been printed in handle_server_response
            gui_callback("Accounts retrieved successfully.", success=True, data=self.last_accounts)
        elif self.list_accounts_response == Operations.FAILURE:
            # The error message has already been printed in handle_server_response
            gui_callback("Failed to retrieve accounts.", success=False)
        else:
            gui_callback("Unexpected list accounts response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def send_chat_message(self, sender, recipient, message, gui_callback):
        """Send a chat message."""
        if not self.username:
            gui_callback("You must be logged in to send messages.", success=False)
            return
        if not recipient or not message:
            gui_callback("Recipient and message cannot be empty.", success=False)
            return

        # Prepare payload as a single string separated by newlines
        payload = "\n".join([sender, recipient, message])

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
        threading.Thread(target=self.wait_for_event, args=(
            self.send_message_event, self.handle_send_message_response, gui_callback), daemon=True).start()

    def handle_send_message_response(self, gui_callback):
        if self.send_message_response == Operations.SUCCESS:
            gui_callback("Message sent successfully.", success=True)
        elif self.send_message_response == Operations.FAILURE:
            gui_callback("Failed to send message.", success=False)
        else:
            gui_callback("Unexpected send message response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def view_messages(self, username, count, gui_callback):
        """Send view messages request."""
        if not self.username:
            gui_callback("You must be logged in to view messages.", success=False)
            return
        try:
            count = int(count)
            if count <= 0:
                gui_callback("Please enter a positive integer.", success=False)
                return
        except ValueError:
            gui_callback("Invalid number entered.", success=False)
            return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'view_msgs'

        # Clear the event and reset the response
        self.view_msgs_event.clear()
        self.view_msgs_response = None

        # Send the VIEW_UNDELIVERED_MESSAGES request
        self.send_message(Operations.VIEW_UNDELIVERED_MESSAGES, [username, str(count)])
        print("Waiting for messages...", flush=True)

        # Wait for the server's response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.view_msgs_event, self.handle_view_messages_response, gui_callback), daemon=True).start()

    def handle_view_messages_response(self, gui_callback):
        if self.view_msgs_response == Operations.SUCCESS:
            # Messages already printed in handle_server_response
            gui_callback("Messages retrieved successfully.", success=True, data=self.last_messages, count=self.number_unread_messages)
        elif self.view_msgs_response == Operations.FAILURE:
            # Error message already printed in handle_server_response
            gui_callback("Failed to retrieve messages.", success=False)
        else:
            gui_callback("Unexpected view messages response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def delete_messages(self, username, delete_info, gui_callback):
        """Send delete messages request."""
        if not self.username:
            gui_callback("You must be logged in to delete messages.", success=False)
            return

        if delete_info.upper() != 'ALL':
            try:
                count = int(delete_info)
                if count <= 0:
                    gui_callback("Please enter a positive integer or 'ALL'.", success=False)
                    return
            except ValueError:
                gui_callback("Invalid input. Enter a positive integer or 'ALL'.", success=False)
                return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'delete_message'

        # Clear the event and reset the response
        self.delete_message_event.clear()
        self.delete_message_response = None

        # Send the DELETE_MESSAGE request
        self.send_message(Operations.DELETE_MESSAGE, [username, delete_info.upper()])
        print("Waiting for delete message response...", flush=True)

        # Wait for the server's response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.delete_message_event, self.handle_delete_messages_response, gui_callback), daemon=True).start()

    def handle_delete_messages_response(self, gui_callback):
        if self.delete_message_response == Operations.SUCCESS:
            gui_callback("Messages deleted successfully.", success=True)
        elif self.delete_message_response == Operations.FAILURE:
            gui_callback("Failed to delete messages.", success=False)
        else:
            gui_callback("Unexpected delete message response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def delete_account(self, username, gui_callback):
        """Send delete account request."""
        if not self.username:
            gui_callback("You must be logged in to delete your account.", success=False)
            return

        # Set current operation
        with self.operation_lock:
            self.current_operation = 'delete_account'

        # Clear the event and reset the response
        self.delete_account_event.clear()
        self.delete_account_response = None

        # Send the DELETE_ACCOUNT request
        self.send_message(Operations.DELETE_ACCOUNT, [username])
        print("Waiting for delete account response...", flush=True)

        # Wait for the server's response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.delete_account_event, self.handle_delete_account_response, gui_callback), daemon=True).start()

    def handle_delete_account_response(self, gui_callback):
        if self.delete_account_response == Operations.SUCCESS:
            gui_callback("Account deleted successfully. You have been logged out.", success=True, deleted=True)
        elif self.delete_account_response in (Operations.FAILURE, Operations.ACCOUNT_DOES_NOT_EXIST):
            gui_callback("Failed to delete account.", success=False)
        else:
            gui_callback("Unexpected delete account response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def logout(self, username, gui_callback):
        """Send logout request."""
        if not self.username:
            gui_callback("You are not logged in.", success=False)
            return
        # Prepare to wait for logout response
        with self.operation_lock:
            self.current_operation = 'logout'
        self.logout_event.clear()
        self.send_message(Operations.LOGOUT, [username])
        print("Waiting for logout response...", flush=True)
        # Wait for the logout response (with a timeout)
        threading.Thread(target=self.wait_for_event, args=(
            self.logout_event, self.handle_logout_response, gui_callback), daemon=True).start()

    def handle_logout_response(self, gui_callback):
        if self.logout_response == Operations.SUCCESS:
            gui_callback("Successfully logged out.", success=True, logged_out=True)
        elif self.logout_response == Operations.FAILURE:
            gui_callback("Logout failed. Please try again.", success=False)
        else:
            gui_callback("Unexpected logout response.", success=False)
        # Reset current_operation
        with self.operation_lock:
            self.current_operation = None

    def wait_for_event(self, event, handler, *args):
        """Wait for an event and then handle it."""
        event_occurred = event.wait(timeout=10)
        if event_occurred:
            handler(*args)
        else:
            # Handle timeout
            handler(None, gui_callback=lambda msg, success=False: messagebox.showerror("Timeout", "No response from server. Please try again later."))

    def close(self):
        """Close the connection to the server."""
        self.running = False
        if self.sock:
            self.sock.close()
            print("Disconnected from server.")


class ChatGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Chat Client")
        self.client = ChatClient(host='localhost', port=5050)
        self.client.connect()

        # Initialize frames
        self.current_frame = None
        self.show_login_register()

    def clear_frame(self):
        """Destroy the current frame."""
        if self.current_frame:
            self.current_frame.destroy()

    def show_login_register(self):
        """Display the login and register options."""
        self.clear_frame()
        frame = tk.Frame(self.master)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Welcome to Chat Client", font=("Helvetica", 16)).pack(pady=10)

        tk.Button(frame, text="Log In", width=20, command=self.show_login).pack(pady=5)
        tk.Button(frame, text="Create Account", width=20, command=self.show_register).pack(pady=5)
        tk.Button(frame, text="Exit", width=20, command=self.master.quit).pack(pady=5)

        self.current_frame = frame

    def show_login(self):
        """Display the login form."""
        self.clear_frame()
        frame = tk.Frame(self.master)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Log In", font=("Helvetica", 16)).pack(pady=10)

        tk.Label(frame, text="Username:").pack()
        username_entry = tk.Entry(frame)
        username_entry.pack(pady=5)

        tk.Label(frame, text="Password:").pack()
        password_entry = tk.Entry(frame, show="*")
        password_entry.pack(pady=5)

        def submit_login():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showwarning("Input Error", "Please enter both username and password.")
                return
            self.client.log_in(username, password, self.handle_login_response)

        tk.Button(frame, text="Log In", width=20, command=submit_login).pack(pady=5)
        tk.Button(frame, text="Back", width=20, command=self.show_login_register).pack(pady=5)

        self.current_frame = frame

    def handle_login_response(self, message, success, **kwargs):
        if success:
            messagebox.showinfo("Success", message)
            self.show_dashboard()
        else:
            messagebox.showerror("Login Failed", message)

    def show_register(self):
        """Display the register form."""
        self.clear_frame()
        frame = tk.Frame(self.master)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Create Account", font=("Helvetica", 16)).pack(pady=10)

        tk.Label(frame, text="Username:").pack()
        username_entry = tk.Entry(frame)
        username_entry.pack(pady=5)

        def submit_register():
            username = username_entry.get().strip()
            if not username:
                messagebox.showwarning("Input Error", "Please enter a username.")
                return
            self.client.try_create_account(username, self.handle_check_username_response)

        tk.Button(frame, text="Check Username", width=20, command=submit_register).pack(pady=5)
        tk.Button(frame, text="Back", width=20, command=self.show_login_register).pack(pady=5)

        self.current_frame = frame

    def handle_check_username_response(self, message, success, username=None, create_account=False):
        if create_account:
            # Prompt for password
            password = simpledialog.askstring("Password", "Enter new password:", show='*')
            if password:
                self.client.create_account(username, password, self.handle_create_account_response)
            else:
                messagebox.showwarning("Input Error", "Password cannot be empty.")
        elif success:
            messagebox.showinfo("Info", message)
        else:
            messagebox.showerror("Error", message)

    def handle_create_account_response(self, message, success, **kwargs):
        if success:
            messagebox.showinfo("Success", message)
            self.show_dashboard()
        else:
            messagebox.showerror("Account Creation Failed", message)

    def show_dashboard(self):
        """Display the main dashboard after login."""
        self.clear_frame()
        frame = tk.Frame(self.master)
        frame.pack(padx=10, pady=10)

        username = self.client.username

        tk.Label(frame, text=f"Welcome, {username}", font=("Helvetica", 16)).pack(pady=10)

        tk.Button(frame, text="List Accounts", width=25, command=self.list_accounts).pack(pady=5)
        tk.Button(frame, text="Send Message", width=25, command=self.send_message).pack(pady=5)
        tk.Button(frame, text="View Messages", width=25, command=self.view_messages).pack(pady=5)
        tk.Button(frame, text="Delete Messages", width=25, command=self.delete_messages).pack(pady=5)
        tk.Button(frame, text="Delete Account", width=25, command=self.delete_account).pack(pady=5)
        tk.Button(frame, text="Logout", width=25, command=self.logout).pack(pady=5)
        tk.Button(frame, text="Exit", width=25, command=self.master.quit).pack(pady=5)

        self.current_frame = frame

    def list_accounts(self):
        """Handle the list accounts operation."""
        pattern = simpledialog.askstring("List Accounts", "Enter username pattern to search for (use * for all):", initialvalue="*")
        if pattern is None:
            return  # User cancelled
        self.client.list_accounts(self.client.username, pattern, self.handle_list_accounts_response)

    def handle_list_accounts_response(self, message, success, data=None, **kwargs):
        if success:
            # Display the accounts in a new window
            accounts_window = tk.Toplevel(self.master)
            accounts_window.title("List of Accounts")
            accounts_window.geometry("400x300")

            text_area = scrolledtext.ScrolledText(accounts_window, wrap=tk.WORD)
            text_area.pack(expand=True, fill='both')
            text_area.insert(tk.END, data)
            text_area.configure(state='disabled')
        else:
            messagebox.showerror("Error", message)

    def send_message(self):
        """Handle sending a message."""
        send_window = tk.Toplevel(self.master)
        send_window.title("Send Message")
        send_window.geometry("400x300")

        tk.Label(send_window, text="Send Message", font=("Helvetica", 14)).pack(pady=10)

        tk.Label(send_window, text="Recipient Username:").pack()
        recipient_entry = tk.Entry(send_window)
        recipient_entry.pack(pady=5)

        tk.Label(send_window, text="Message:").pack()
        message_text = scrolledtext.ScrolledText(send_window, height=10)
        message_text.pack(pady=5)

        def submit_message():
            recipient = recipient_entry.get().strip()
            message = message_text.get("1.0", tk.END).strip()
            if not recipient or not message:
                messagebox.showwarning("Input Error", "Please enter both recipient and message.")
                return
            self.client.send_chat_message(self.client.username, recipient, message, self.handle_send_message_response)
            send_window.destroy()

        tk.Button(send_window, text="Send", width=15, command=submit_message).pack(pady=5)

    def handle_send_message_response(self, message, success, **kwargs):
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)

    def view_messages(self):
        """Handle viewing messages."""
        count = simpledialog.askinteger("View Messages", "Enter the number of messages to retrieve:", minvalue=1)
        if count is None:
            return  # User cancelled
        self.client.view_messages(self.client.username, count, self.handle_view_messages_response)

    def handle_view_messages_response(self, message, success, data=None, count=None, **kwargs):
        if success:
            # Display the messages in a new window
            messages_window = tk.Toplevel(self.master)
            messages_window.title("Your Messages")
            messages_window.geometry("500x400")

            tk.Label(messages_window, text="Your Messages", font=("Helvetica", 14)).pack(pady=10)

            text_area = scrolledtext.ScrolledText(messages_window, wrap=tk.WORD)
            text_area.pack(expand=True, fill='both')
            text_area.insert(tk.END, data)
            text_area.configure(state='disabled')

            tk.Label(messages_window, text=f"Number of unread messages: {count}").pack(pady=5)
        else:
            messagebox.showerror("Error", message)

    def delete_messages(self):
        """Handle deleting messages."""
        delete_info = simpledialog.askstring("Delete Messages", "Enter 'ALL' to delete all messages or the number of messages to delete:")
        if delete_info is None:
            return  # User cancelled
        self.client.delete_messages(self.client.username, delete_info, self.handle_delete_messages_response)

    def handle_delete_messages_response(self, message, success, **kwargs):
        if success:
            messagebox.showinfo("Success", message)
        else:
            messagebox.showerror("Error", message)

    def delete_account(self):
        """Handle deleting account."""
        confirmation = messagebox.askyesno("Delete Account", "Are you sure you want to delete your account? This action cannot be undone.")
        if confirmation:
            self.client.delete_account(self.client.username, self.handle_delete_account_response)

    def handle_delete_account_response(self, message, success, deleted=False, **kwargs):
        if success and deleted:
            messagebox.showinfo("Success", message)
            self.show_login_register()
        else:
            messagebox.showerror("Error", message)

    def logout(self):
        """Handle user logout."""
        self.client.logout(self.client.username, self.handle_logout_response)

    def handle_logout_response(self, message, success, logged_out=False, **kwargs):
        if success and logged_out:
            messagebox.showinfo("Success", message)
            self.show_login_register()
        elif success:
            messagebox.showinfo("Success", message)
            self.show_login_register()
        else:
            messagebox.showerror("Error", message)


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()