# client_gui.py

import socket
import struct
import sys
import threading
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from serialization import serialize_custom, deserialize_custom
from operations import Operations
from bcrypt_utils import hash_password  # For hashing passwords with bcrypt


class ChatClientGUI:
    def __init__(self, master, host='localhost', port=5050):
        self.master = master
        self.master.title("Chat Client")
        self.master.geometry("600x500")

        self.server_host = host
        self.server_port = port
        self.sock = None
        self.receive_thread = None
        self.running = False
        self.username = None
        self.number_unread_messages = 0

        # Events and responses
        self.lock = threading.Lock()
        self.current_operation = None
        self.events = {
            'check_username': threading.Event(),
            'create_account': threading.Event(),
            'login': threading.Event(),
            'logout': threading.Event(),
            'list_accounts': threading.Event(),
            'send_message': threading.Event(),
        }
        self.responses = {
            'check_username': None,
            'create_account': None,
            'login': None,
            'logout': None,
            'list_accounts': None,
            'send_message': None,
        }

        # Setup GUI Frames
        self.setup_login_frame()
        self.setup_create_account_frame()
        self.setup_main_frame()

        # Initially show login frame
        self.login_frame.pack()

        # Start connection
        self.connect()

    def setup_login_frame(self):
        self.login_frame = tk.Frame(self.master)

        tk.Label(self.login_frame, text="Login", font=("Helvetica", 16, "bold")).pack(pady=10)

        form_frame = tk.Frame(self.login_frame)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Username:", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=5, sticky='e')
        self.login_username_entry = tk.Entry(form_frame, font=("Helvetica", 12))
        self.login_username_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(form_frame, text="Password:", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=5, sticky='e')
        self.login_password_entry = tk.Entry(form_frame, show="*", font=("Helvetica", 12))
        self.login_password_entry.grid(row=1, column=1, padx=10, pady=5)

        button_frame = tk.Frame(self.login_frame)
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Log In", width=10, command=self.log_in).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="Create Account", width=15, command=self.show_create_account_frame).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="Exit", width=10, command=self.close).grid(row=0, column=2, padx=5)

    def setup_create_account_frame(self):
        self.create_account_frame = tk.Frame(self.master)

        tk.Label(self.create_account_frame, text="Create Account", font=("Helvetica", 16, "bold")).pack(pady=10)

        form_frame = tk.Frame(self.create_account_frame)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Username:", font=("Helvetica", 12)).grid(row=0, column=0, padx=10, pady=5, sticky='e')
        self.create_username_entry = tk.Entry(form_frame, font=("Helvetica", 12))
        self.create_username_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(form_frame, text="Password:", font=("Helvetica", 12)).grid(row=1, column=0, padx=10, pady=5, sticky='e')
        self.create_password_entry = tk.Entry(form_frame, show="*", font=("Helvetica", 12))
        self.create_password_entry.grid(row=1, column=1, padx=10, pady=5)

        button_frame = tk.Frame(self.create_account_frame)
        button_frame.pack(pady=20)

        tk.Button(button_frame, text="Submit", width=10, command=self.submit_create_account).grid(row=0, column=0, padx=5)
        tk.Button(button_frame, text="Back to Login", width=15, command=self.show_login_frame).grid(row=0, column=1, padx=5)
        tk.Button(button_frame, text="Exit", width=10, command=self.close).grid(row=0, column=2, padx=5)

    def setup_main_frame(self):
        self.main_frame = tk.Frame(self.master)

        # Top Frame for welcome message and logout
        top_frame = tk.Frame(self.main_frame)
        top_frame.pack(fill='x', pady=5)

        self.welcome_label = tk.Label(top_frame, text="Welcome!", font=("Helvetica", 14))
        self.welcome_label.pack(side='left', padx=10)

        tk.Button(top_frame, text="Logout", command=self.logout).pack(side='right', padx=10)

        # Middle Frame for message display
        middle_frame = tk.Frame(self.main_frame)
        middle_frame.pack(fill='both', expand=True, padx=10, pady=5)

        # Canvas and scrollbar for messages
        self.canvas = tk.Canvas(middle_frame, bg="#F5F5F5")
        self.scrollbar = tk.Scrollbar(middle_frame, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = tk.Frame(self.canvas, bg="#F5F5F5")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Bottom Frame for actions
        bottom_frame = tk.Frame(self.main_frame)
        bottom_frame.pack(fill='x', pady=5)

        tk.Button(bottom_frame, text="List Accounts", width=15, command=self.list_accounts).pack(side='left', padx=5)
        tk.Button(bottom_frame, text="Send Message", width=15, command=self.send_chat_message).pack(side='left', padx=5)
        tk.Button(bottom_frame, text="Exit", width=10, command=self.close).pack(side='right', padx=5)

    def connect(self):
        """Establish a connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.running = True
            self.log_message(f"Connected to server at {self.server_host}:{self.server_port}", system=True)

            # Start a thread to listen for incoming messages.
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            self.master.destroy()

    def send_message(self, message_type: Operations, payload: list):
        """Serialize and send a message to the server."""
        try:
            serialized = serialize_custom(message_type, payload)
            self.sock.sendall(serialized)
            # For outgoing messages, log them as system messages or user messages
            if message_type == Operations.SEND_MESSAGE:
                recipient = payload[0].split("\n")[1]
                message = payload[0].split("\n")[2]
                self.display_user_message(f"To {recipient}: {message}")
        except Exception as e:
            self.log_message(f"Failed to send message: {e}", system=True)

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
                    self.log_message("Server closed the connection.", system=True)
                    self.running = False
                    break

                msg_type, payload_length = struct.unpack("!I I", header)

                # Now receive the payload.
                payload_bytes = self.recvall(payload_length)
                if len(payload_bytes) != payload_length:
                    self.log_message("Incomplete payload received.", system=True)
                    continue

                # Deserialize the full message (header + payload)
                msg_type_received, payload_received = deserialize_custom(header + payload_bytes)
                self.handle_server_response(msg_type_received, payload_received)
            except Exception as e:
                self.log_message(f"Error receiving message: {e}", system=True)
                self.running = False
                break

    def handle_server_response(self, msg_type, payload):
        """Handle and display the server's response."""
        try:
            operation = Operations(msg_type)

            if operation == Operations.RECEIVE_CURRENT_MESSAGE:
                # Display the incoming message immediately
                sender = payload[0].split("\n")[0]
                message = payload[0].split("\n")[2]
                self.display_incoming_message(sender, message)
                return  # Return early to avoid processing it as part of current_operation

            self.log_message(f"Server Response: {operation.name}, Payload: {payload}", system=True)

            with self.lock:
                current_op = self.current_operation

            if current_op is None:
                self.log_message("No operation is currently awaiting a response.", system=True)
                return

            if current_op == 'check_username':
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    self.responses['check_username'] = operation
                    self.events['check_username'].set()
                else:
                    self.log_message("Unexpected response for CHECK_USERNAME operation.", system=True)
                    self.events['check_username'].set()

            elif current_op == 'create_account':
                if operation == Operations.SUCCESS:
                    if len(payload) >= 3:
                        self.username = payload[0]
                        try:
                            self.number_unread_messages = int(payload[2])
                        except ValueError:
                            self.number_unread_messages = 0
                    self.log_message(f"Account created successfully. You are now logged in as: {self.username}", system=True)
                    self.log_message(f"Number of unread messages: {self.number_unread_messages}", system=True)
                    self.responses['create_account'] = Operations.SUCCESS
                    self.events['create_account'].set()
                    self.switch_to_main_frame()
                elif operation == Operations.FAILURE:
                    self.log_message("Account creation failed. Please try again.", system=True)
                    self.responses['create_account'] = Operations.FAILURE
                    self.events['create_account'].set()
                else:
                    self.log_message("Unexpected response for CREATE_ACCOUNT operation.", system=True)
                    self.events['create_account'].set()

            elif current_op == 'login':
                if operation == Operations.SUCCESS:
                    if len(payload) >= 3:
                        self.username = payload[0]
                        try:
                            self.number_unread_messages = int(payload[2])
                        except ValueError:
                            self.number_unread_messages = 0
                    self.log_message(f"Logged in as: {self.username}", system=True)
                    self.log_message(f"Number of unread messages: {self.number_unread_messages}", system=True)
                    self.responses['login'] = Operations.SUCCESS
                    self.events['login'].set()
                    self.switch_to_main_frame()
                elif operation == Operations.FAILURE:
                    self.log_message("Authentication failed. Please try again.", system=True)
                    self.responses['login'] = Operations.FAILURE
                    self.events['login'].set()
                else:
                    self.log_message("Unexpected response for LOGIN operation.", system=True)
                    self.events['login'].set()

            elif current_op == 'logout':
                if operation == Operations.SUCCESS:
                    self.log_message("Successfully logged out.", system=True)
                    self.responses['logout'] = Operations.SUCCESS
                    self.events['logout'].set()
                    self.username = None
                    self.number_unread_messages = 0
                    self.switch_to_login_frame()
                elif operation == Operations.FAILURE:
                    self.log_message("Logout failed. Please try again.", system=True)
                    self.responses['logout'] = Operations.FAILURE
                    self.events['logout'].set()
                else:
                    self.log_message("Unexpected response for LOGOUT operation.", system=True)
                    self.events['logout'].set()

            elif current_op == 'list_accounts':
                if operation == Operations.SUCCESS:
                    accounts = payload[0]  # Assuming the first payload element is the accounts string
                    self.log_message("Accounts:\n" + accounts, system=True)
                    self.responses['list_accounts'] = Operations.SUCCESS
                    self.events['list_accounts'].set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to retrieve accounts."
                    self.log_message(f"Failed to list accounts: {error_message}", system=True)
                    self.responses['list_accounts'] = Operations.FAILURE
                    self.events['list_accounts'].set()
                else:
                    self.log_message("Unexpected response for LIST_ACCOUNTS operation.", system=True)
                    self.events['list_accounts'].set()

            elif current_op == 'send_message':
                if operation == Operations.SUCCESS:
                    success_message = payload[0] if payload else "Message sent successfully."
                    self.log_message(success_message, system=True)
                    self.responses['send_message'] = Operations.SUCCESS
                    self.events['send_message'].set()
                elif operation == Operations.FAILURE:
                    error_message = payload[0] if payload else "Failed to send message."
                    self.log_message(f"Failed to send message: {error_message}", system=True)
                    self.responses['send_message'] = Operations.FAILURE
                    self.events['send_message'].set()
                else:
                    self.log_message("Unexpected response for SEND_MESSAGE operation.", system=True)
                    self.events['send_message'].set()

            else:
                self.log_message(f"Unhandled current operation: {current_op}", system=True)
        except ValueError:
            self.log_message(f"Unknown message type received: {msg_type}, Payload: {payload}", system=True)

    def log_message(self, message, system=False):
        """Log a system message to the messages_display widget in a thread-safe manner."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if system:
            formatted_message = f"[{timestamp}] {message}"
            self.display_system_message(formatted_message)
        else:
            self.display_system_message(message)

    def display_system_message(self, message):
        """Display a system message in the chat area."""
        message_frame = tk.Frame(self.scrollable_frame, bg="#F5F5F5", pady=5)
        message_label = tk.Label(message_frame, text=message, bg="#F5F5F5", fg="#555555", font=("Helvetica", 10), wraplength=500, justify='left')
        message_label.pack(anchor='w')
        message_frame.pack(fill='x', anchor='w')

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def display_user_message(self, message):
        """Display an outgoing message in the chat area."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message_frame = tk.Frame(self.scrollable_frame, bg="#DCF8C6", pady=5)
        message_label = tk.Label(message_frame, text=f"[{timestamp}] {message}", bg="#DCF8C6", fg="#000000", font=("Helvetica", 10), wraplength=500, justify='left')
        message_label.pack(anchor='e')
        message_frame.pack(fill='x', anchor='e', pady=2)

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def display_incoming_message(self, sender, message):
        """Display an incoming message in the chat area."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        message_frame = tk.Frame(self.scrollable_frame, bg="#FFFFFF", pady=5)
        sender_label = tk.Label(message_frame, text=f"{sender} [{timestamp}]:", bg="#FFFFFF", fg="#1E90FF", font=("Helvetica", 10, "bold"))
        sender_label.pack(anchor='w')
        message_label = tk.Label(message_frame, text=message, bg="#FFFFFF", fg="#000000", font=("Helvetica", 10), wraplength=500, justify='left')
        message_label.pack(anchor='w')
        message_frame.pack(fill='x', anchor='w', pady=2)

        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

    def switch_to_main_frame(self):
        self.login_frame.pack_forget()
        self.create_account_frame.pack_forget()
        self.main_frame.pack()
        self.welcome_label.config(text=f"Welcome, {self.username}!")

    def switch_to_login_frame(self):
        self.main_frame.pack_forget()
        self.create_account_frame.pack_forget()
        self.login_frame.pack()
        self.login_username_entry.delete(0, tk.END)
        self.login_password_entry.delete(0, tk.END)

    def show_create_account_frame(self):
        self.login_frame.pack_forget()
        self.create_account_frame.pack()

    def show_login_frame(self):
        self.create_account_frame.pack_forget()
        self.login_frame.pack()

    def try_create_account(self):
        """Initiate account creation process."""
        # This method is no longer needed since we're using separate frames
        pass

    def submit_create_account(self):
        """Handle Create Account submission."""
        username = self.create_username_entry.get().strip()
        password = self.create_password_entry.get().strip()

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty.")
            return

        hashed_password = hash_password(password)

        with self.lock:
            self.current_operation = 'check_username'

        self.events['check_username'].clear()
        self.send_message(Operations.CHECK_USERNAME, [username])

        # Wait for the server's response in a separate thread to avoid blocking the GUI
        threading.Thread(target=self.wait_for_event, args=('check_username', self.handle_create_account_response, username), daemon=True).start()

    def handle_create_account_response(self, username):
        event = self.events['check_username']
        event.wait(timeout=10)
        response = self.responses['check_username']
        if response == Operations.ACCOUNT_DOES_NOT_EXIST:
            self.create_account(username)
        elif response == Operations.ACCOUNT_ALREADY_EXISTS:
            messagebox.showinfo("Account Exists", "Account already exists. Please log in.")
            self.show_login_frame()
        else:
            messagebox.showerror("Error", "Unexpected response received.")

        # Reset current operation
        with self.lock:
            self.current_operation = None

    def create_account(self, username):
        """Send account creation request with hashed password."""
        password = self.create_password_entry.get().strip()
        if not password:
            messagebox.showwarning("Input Error", "Password cannot be empty.")
            return

        hashed_password = hash_password(password)

        with self.lock:
            self.current_operation = 'create_account'

        self.events['create_account'].clear()
        self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password.decode('utf-8')])

        # Wait for the server's response in a separate thread
        threading.Thread(target=self.wait_for_event, args=('create_account', self.handle_create_account_completion), daemon=True).start()

    def handle_create_account_completion(self):
        event = self.events['create_account']
        event.wait(timeout=10)
        response = self.responses['create_account']
        if response == Operations.SUCCESS:
            self.switch_to_main_frame()
        elif response == Operations.FAILURE:
            messagebox.showerror("Creation Failed", "Account creation failed. Please try again.")
        else:
            messagebox.showerror("Error", "Unexpected response received.")

    def log_in(self):
        """Handle user login."""
        username = self.login_username_entry.get().strip()
        password = self.login_password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty.")
            return

        hashed_password = hash_password(password)

        with self.lock:
            self.current_operation = 'login'

        self.events['login'].clear()
        self.send_message(Operations.LOGIN, [username, hashed_password.decode('utf-8')])

        # Wait for the server's response in a separate thread
        threading.Thread(target=self.wait_for_event, args=('login', self.handle_login_response), daemon=True).start()

    def handle_login_response(self):
        event = self.events['login']
        event.wait(timeout=10)
        response = self.responses['login']
        if response == Operations.SUCCESS:
            self.switch_to_main_frame()
        elif response == Operations.FAILURE:
            messagebox.showerror("Login Failed", "Authentication failed. Please try again.")
        else:
            messagebox.showerror("Error", "Unexpected response received.")

    def list_accounts(self):
        """Handle listing of accounts."""
        if not self.username:
            messagebox.showwarning("Not Logged In", "You must be logged in to list accounts.")
            return

        pattern = tk.simpledialog.askstring("List Accounts", "Enter a username pattern to search for:", initialvalue="*", parent=self.master)
        if pattern is None:
            return  # User cancelled
        pattern = pattern.strip() or "*"

        with self.lock:
            self.current_operation = 'list_accounts'

        self.events['list_accounts'].clear()
        self.send_message(Operations.LIST_ACCOUNTS, [self.username, pattern])

        # Wait for the server's response in a separate thread
        threading.Thread(target=self.wait_for_event, args=('list_accounts', self.handle_list_accounts_response), daemon=True).start()

    def handle_list_accounts_response(self):
        event = self.events['list_accounts']
        event.wait(timeout=10)
        response = self.responses['list_accounts']
        if response == Operations.SUCCESS:
            pass  # Already handled in handle_server_response
        elif response == Operations.FAILURE:
            pass  # Already handled in handle_server_response
        else:
            messagebox.showerror("Error", "Unexpected response received.")

    def send_chat_message(self):
        """Handle sending a chat message."""
        if not self.username:
            messagebox.showwarning("Not Logged In", "You must be logged in to send messages.")
            return

        # Prompt for recipient
        recipient = tk.simpledialog.askstring("Send Message", "Enter recipient username:", parent=self.master)
        if not recipient:
            messagebox.showwarning("Input Error", "Recipient cannot be empty.")
            return

        # Prompt for message
        message = tk.simpledialog.askstring("Send Message", "Enter message:", parent=self.master)
        if not message:
            messagebox.showwarning("Input Error", "Message cannot be empty.")
            return

        payload = "\n".join([self.username, recipient, message])

        with self.lock:
            self.current_operation = 'send_message'

        self.events['send_message'].clear()
        self.send_message(Operations.SEND_MESSAGE, [payload])

        # Wait for the server's response in a separate thread
        threading.Thread(target=self.wait_for_event, args=('send_message', self.handle_send_message_response), daemon=True).start()

    def handle_send_message_response(self):
        event = self.events['send_message']
        event.wait(timeout=10)
        response = self.responses['send_message']
        if response == Operations.SUCCESS:
            messagebox.showinfo("Success", "Message sent successfully.")
        elif response == Operations.FAILURE:
            messagebox.showerror("Failure", "Failed to send message.")
        else:
            messagebox.showerror("Error", "Unexpected response received.")

    def logout(self):
        """Handle user logout."""
        if not self.username:
            messagebox.showwarning("Not Logged In", "You are not logged in.")
            return

        with self.lock:
            self.current_operation = 'logout'

        self.events['logout'].clear()
        self.send_message(Operations.LOGOUT, [self.username])

        # Wait for the server's response in a separate thread
        threading.Thread(target=self.wait_for_event, args=('logout', self.handle_logout_response), daemon=True).start()

    def handle_logout_response(self):
        event = self.events['logout']
        event.wait(timeout=10)
        response = self.responses['logout']
        if response == Operations.SUCCESS:
            self.switch_to_login_frame()
        elif response == Operations.FAILURE:
            messagebox.showerror("Logout Failed", "Logout failed. Please try again.")
        else:
            messagebox.showerror("Error", "Unexpected response received.")

    def wait_for_event(self, operation, callback, *args):
        """Wait for a specific event and then call the callback."""
        event = self.events.get(operation)
        if event:
            event.wait(timeout=10)
            callback(*args)

    def close(self):
        """Close the connection to the server and exit."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
                self.log_message("Disconnected from server.", system=True)
            except Exception:
                pass
        self.master.destroy()


def main():
    # Set up connection parameters.
    PORT = 5050  # Port to connect to.
    SERVER_HOST_NAME = socket.gethostname()  # Host name of the machine.
    SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)  # IPv4 address of the machine.

    root = tk.Tk()
    client_gui = ChatClientGUI(root, host=SERVER_HOST, port=PORT)
    root.protocol("WM_DELETE_WINDOW", client_gui.close)
    root.mainloop()


if __name__ == "__main__":
    main()