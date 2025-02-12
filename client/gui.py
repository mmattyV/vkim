import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import sys
import os
from datetime import datetime
import struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))
from serialization import serialize_custom, deserialize_custom
from operations import Operations
from hash_utils import hash_password

class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Client")
        self.root.geometry("800x600")
        
        # Initialize client attributes
        self.server_host = socket.gethostbyname(socket.gethostname())
        self.server_port = 5050
        self.sock = None
        self.receive_thread = None
        self.running = False
        self.username = None
        self.number_unread_messages = 0
        
        # Create and initialize frames
        self.init_frames()
        self.show_login_frame()
        
        # Initialize events and responses similar to original client
        self.init_events()
        
        # Initialize the operation lock
        self.operation_lock = threading.Lock()
        self.current_operation = None
        
    def init_frames(self):
        """Initialize all frames for different views"""
        # Login Frame
        self.login_frame = ttk.Frame(self.root)
        self.create_login_widgets()
        
        # Main Chat Frame
        self.chat_frame = ttk.Frame(self.root)
        self.create_chat_widgets()
        
    def create_login_widgets(self):
        """Create widgets for login frame"""
        # Username Entry
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        
        # Password Entry
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        
        # Login Button
        ttk.Button(self.login_frame, text="Login", command=self.handle_login).pack(pady=10)
        
        # Create Account Button
        ttk.Button(self.login_frame, text="Create Account", 
                  command=self.show_create_account_dialog).pack(pady=5)
    
    def create_chat_widgets(self):
        """Create widgets for main chat frame"""
        # Create left and right panes
        left_pane = ttk.Frame(self.chat_frame)
        left_pane.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_pane = ttk.Frame(self.chat_frame)
        right_pane.pack(side=tk.RIGHT, fill=tk.BOTH)
        
        # Message Display Area
        self.message_area = scrolledtext.ScrolledText(left_pane, wrap=tk.WORD, 
                                                    width=50, height=20)
        self.message_area.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Message Input Area
        self.message_input = scrolledtext.ScrolledText(left_pane, wrap=tk.WORD, 
                                                     width=50, height=4)
        self.message_input.pack(padx=5, pady=5, fill=tk.X)
        
        # Recipient Entry
        recipient_frame = ttk.Frame(left_pane)
        recipient_frame.pack(fill=tk.X, padx=5)
        ttk.Label(recipient_frame, text="To:").pack(side=tk.LEFT)
        self.recipient_entry = ttk.Entry(recipient_frame)
        self.recipient_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Send Button
        ttk.Button(left_pane, text="Send", 
                  command=self.send_chat_message).pack(pady=5)
        
        # Right side buttons
        ttk.Button(right_pane, text="View Messages", 
                  command=self.view_messages).pack(pady=5, padx=5, fill=tk.X)
        ttk.Button(right_pane, text="List Accounts", 
                  command=self.list_accounts).pack(pady=5, padx=5, fill=tk.X)
        ttk.Button(right_pane, text="Delete Messages", 
                  command=self.show_delete_messages_dialog).pack(pady=5, padx=5, fill=tk.X)
        ttk.Button(right_pane, text="Delete Account", 
                  command=self.confirm_delete_account).pack(pady=5, padx=5, fill=tk.X)
        ttk.Button(right_pane, text="Logout", 
                  command=self.logout).pack(pady=5, padx=5, fill=tk.X)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.chat_frame, textvariable=self.status_var)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def init_events(self):
        """Initialize all events and responses"""
        self.check_username_event = threading.Event()
        self.account_exists_response = None
        
        self.login_event = threading.Event()
        self.login_response = None
        
        self.logout_event = threading.Event()
        self.logout_response = None
        
        self.create_account_event = threading.Event()
        self.create_account_response = None
        
        self.list_accounts_event = threading.Event()
        self.list_accounts_response = None
        
        self.send_message_event = threading.Event()
        self.send_message_response = None
        
        self.view_msgs_event = threading.Event()
        self.view_msgs_response = None
        
        self.delete_message_event = threading.Event()
        self.delete_message_response = None
        
        self.delete_account_event = threading.Event()
        self.delete_account_response = None
    
    def show_login_frame(self):
        """Show the login frame and hide others"""
        self.chat_frame.pack_forget()
        self.login_frame.pack(expand=True)
        
    def show_chat_frame(self):
        """Show the chat frame and hide others"""
        self.login_frame.pack_forget()
        self.chat_frame.pack(expand=True, fill=tk.BOTH)
        
    def connect_to_server(self):
        """Establish connection to the server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_host, self.server_port))
            self.running = True
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_messages, 
                                                daemon=True)
            self.receive_thread.start()
            return True
        except Exception as e:
            messagebox.showerror("Connection Error", 
                               f"Failed to connect to server: {str(e)}")
            return False
            
    def handle_login(self):
        """Handle the login process"""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
            
        if not self.running and not self.connect_to_server():
            return
            
        hashed_password = hash_password(password)
        
        with self.operation_lock:
            self.current_operation = 'login'
        
        self.login_event.clear()
        self.send_message(Operations.LOGIN, [username, hashed_password])
        
        # Use after to check the event status
        self.root.after(100, self.check_login_response)
        
    def handle_login_response(self, operation, payload):
        """Handle the login response from the server"""
        if operation == Operations.SUCCESS:
            # Assuming the server sends the username and number of unread messages
            if len(payload) >= 3:
                self.username = payload[0]
                try:
                    self.number_unread_messages = int(payload[2])
                except ValueError:
                    self.number_unread_messages = 0
            self.login_response = Operations.SUCCESS
            self.show_chat_frame()
            self.status_var.set(f"Logged in as: {self.username} ({self.number_unread_messages} unread)")
        elif operation == Operations.FAILURE:
            self.login_response = Operations.FAILURE
            messagebox.showerror("Login Failed", "Invalid username or password")
        
        self.login_event.set()
        with self.operation_lock:
            self.current_operation = None

    def check_login_response(self):
        """Check login response in a non-blocking way"""
        if not self.login_event.is_set():
            # Check again after 100ms if no response yet
            self.root.after(100, self.check_login_response)
            
    def send_message(self, message_type: Operations, payload: list):
        """Send a message to the server"""
        try:
            serialized = serialize_custom(message_type, payload)
            self.sock.sendall(serialized)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            
    def receive_messages(self):
        """Handle incoming messages from server"""
        while self.running:
            try:
                header = self.recvall(8)
                if not header:
                    self.running = False
                    break
                    
                msg_type, payload_length = struct.unpack("!I I", header)
                payload_bytes = self.recvall(payload_length)
                
                if len(payload_bytes) != payload_length:
                    continue
                    
                msg_type_received, payload_received = deserialize_custom(
                    header + payload_bytes)
                
                # Use after to handle the response in the main thread
                self.root.after(0, self.handle_server_response, 
                              msg_type_received, payload_received)
                
            except Exception as e:
                if self.running:
                    self.root.after(0, messagebox.showerror, 
                                  "Error", f"Connection error: {str(e)}")
                    self.running = False
                break
                
    def handle_send_message_response(self, operation, payload):
        """Handle response after sending a message"""
        if operation == Operations.SUCCESS:
            self.display_message("Message sent successfully")
            self.send_message_response = Operations.SUCCESS
        elif operation == Operations.FAILURE:
            error_message = payload[0] if payload else "Failed to send message"
            messagebox.showerror("Error", error_message)
            self.send_message_response = Operations.FAILURE
        self.send_message_event.set()
        
    def handle_create_account_response(self, operation, payload):
        """Handle response after creating an account"""
        if operation == Operations.SUCCESS:
            if len(payload) >= 3:
                self.username = payload[0]
                try:
                    self.number_unread_messages = int(payload[2])
                except ValueError:
                    self.number_unread_messages = 0
            self.create_account_response = Operations.SUCCESS
            messagebox.showinfo("Success", "Account created successfully")
        elif operation == Operations.FAILURE:
            self.create_account_response = Operations.FAILURE
            messagebox.showerror("Error", "Failed to create account")
        self.create_account_event.set()
        
    def handle_list_accounts_response(self, operation, payload):
        """Handle response after listing accounts"""
        if operation == Operations.SUCCESS:
            accounts = payload[0] if payload else "No accounts found"
            if hasattr(self, 'list_accounts_result'):
                self.list_accounts_result.delete('1.0', tk.END)
                self.list_accounts_result.insert('1.0', accounts)
        elif operation == Operations.FAILURE:
            error_message = payload[0] if payload else "Failed to list accounts"
            messagebox.showerror("Error", error_message)
        self.list_accounts_event.set()
        
    def handle_view_messages_response(self, operation, payload):
        """Handle response after viewing messages"""
        if operation == Operations.SUCCESS:
            messages = payload[0]
            count_info = payload[1] if len(payload) > 1 else ""
            try:
                message_count = int(count_info.split()[0])
                self.number_unread_messages -= message_count
                if self.number_unread_messages < 0:
                    self.number_unread_messages = 0
            except (IndexError, ValueError):
                pass
            self.display_message("\nReceived Messages:\n" + messages)
            self.status_var.set(f"Logged in as: {self.username} ({self.number_unread_messages} unread)")
        elif operation == Operations.FAILURE:
            error_message = payload[0] if payload else "Failed to retrieve messages"
            messagebox.showerror("Error", error_message)
        self.view_msgs_event.set()
        
    def handle_delete_message_response(self, operation, payload):
        """Handle response after deleting messages"""
        if operation == Operations.SUCCESS:
            success_message = payload[0] if payload else "Messages deleted successfully"
            messagebox.showinfo("Success", success_message)
        elif operation == Operations.FAILURE:
            error_message = payload[0] if payload else "Failed to delete messages"
            messagebox.showerror("Error", error_message)
        self.delete_message_event.set()
        
    def handle_delete_account_response(self, operation, payload):
        """Handle response after deleting account"""
        if operation == Operations.SUCCESS:
            success_message = payload[0] if payload else "Account deleted successfully"
            messagebox.showinfo("Success", success_message)
            self.username = None
            self.number_unread_messages = 0
            self.show_login_frame()
        elif operation in (Operations.FAILURE, Operations.ACCOUNT_DOES_NOT_EXIST):
            error_message = payload[0] if payload else "Failed to delete account"
            messagebox.showerror("Error", error_message)
        self.delete_account_event.set()
        
    def handle_logout_response(self, operation, payload):
        """Handle response after logging out"""
        if operation == Operations.SUCCESS:
            self.username = None
            self.number_unread_messages = 0
            self.show_login_frame()
            messagebox.showinfo("Success", "Logged out successfully")
        elif operation == Operations.FAILURE:
            error_message = payload[0] if payload else "Failed to logout"
            messagebox.showerror("Error", error_message)
        self.logout_event.set()

    def handle_server_response(self, msg_type, payload):
        """Handle server responses"""
        try:
            operation = Operations(msg_type)
            
            if operation == Operations.RECEIVE_CURRENT_MESSAGE:
                self.display_message(f"[New Message from {payload[1]}]: {payload[0]}")
                return
                
            with self.operation_lock:
                current_op = self.current_operation
                
            print(f"Current operation: {current_op}, Received operation: {operation}")
            
            if current_op == 'check_username':
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    self.account_exists_response = operation
                    self.check_username_event.set()
            elif current_op == 'login':
                self.handle_login_response(operation, payload)
            elif current_op == 'send_message':
                self.handle_send_message_response(operation, payload)
            elif current_op == 'create_account':
                self.handle_create_account_response(operation, payload)
            elif current_op == 'list_accounts':
                self.handle_list_accounts_response(operation, payload)
            elif current_op == 'view_msgs':
                self.handle_view_messages_response(operation, payload)
            elif current_op == 'delete_message':
                self.handle_delete_message_response(operation, payload)
            elif current_op == 'delete_account':
                self.handle_delete_account_response(operation, payload)
            elif current_op == 'logout':
                self.handle_logout_response(operation, payload)
                
        except ValueError as e:
            print(f"Error in handle_server_response: {e}")
            messagebox.showerror("Error", f"Unknown message type: {msg_type}")
            
    def check_username_response(self, check_dialog):
        """Check username availability response"""
        try:
            if self.check_username_event.is_set():
                print("Username check event is set")
                print(f"Account exists response: {self.account_exists_response}")
                
                if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                    print("Username is available, showing password dialog")
                    check_dialog.destroy()
                    self.show_password_dialog(self.temp_username)
                elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                    print("Username exists, showing error")
                    messagebox.showerror("Error", "Account already exists. Please try a different username.")
                else:
                    print(f"Unexpected response: {self.account_exists_response}")
                    messagebox.showerror("Error", "Unexpected response from server")
                
                with self.operation_lock:
                    self.current_operation = None
                    print("Reset current operation")
            else:
                print("Username check event not set, checking again in 100ms")
                self.root.after(100, lambda: self.check_username_response(check_dialog))
                
        except Exception as e:
            print(f"Error in check_username_response: {e}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            
    def display_message(self, message):
        """Display a message in the message area"""
        self.message_area.insert(tk.END, 
                               f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.message_area.see(tk.END)
        
    def send_chat_message(self):
        """Send a chat message"""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in to send messages")
            return
            
        recipient = self.recipient_entry.get().strip()
        message = self.message_input.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showerror("Error", 
                               "Recipient and message cannot be empty")
            return
            
        payload = "\n".join([self.username, recipient, message])
        
        with self.operation_lock:
            self.current_operation = 'send_message'
            
        self.send_message_event.clear()
        self.send_message(Operations.SEND_MESSAGE, [payload])
        
        # Clear message input
        self.message_input.delete("1.0", tk.END)
        
    def view_messages(self):
        """Show dialog to view messages"""
        if not self.username:
            messagebox.showerror("Error", 
                               "You must be logged in to view messages")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("View Messages")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="Enter number of messages to retrieve:").pack(pady=10)
        count_entry = ttk.Entry(dialog)
        count_entry.pack(pady=5)
        
        def retrieve_messages():
            try:
                count = int(count_entry.get().strip())
                if count <= 0:
                    messagebox.showerror("Error", "Please enter a positive number")
                    return
                    
                with self.operation_lock:
                    self.current_operation = 'view_msgs'
                    
                self.view_msgs_event.clear()
                self.send_message(Operations.VIEW_UNDELIVERED_MESSAGES, 
                                [self.username, str(count)])
                dialog.destroy()
                
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid number")
                
        ttk.Button(dialog, text="Retrieve", command=retrieve_messages).pack(pady=10)
        
    def show_delete_messages_dialog(self):
        """Show dialog to delete messages"""
        if not self.username:
            messagebox.showerror("Error", 
                               "You must be logged in to delete messages")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Delete Messages")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, 
                 text="Enter 'ALL' or number of messages to delete:").pack(pady=10)
        delete_entry = ttk.Entry(dialog)
        delete_entry.pack(pady=5)
        
        def delete_messages():
            delete_info = delete_entry.get().strip()
            if not delete_info:
                messagebox.showerror("Error", "Input cannot be empty")
                return
                
            if delete_info.upper() != 'ALL':
                try:
                    count = int(delete_info)
                    if count <= 0:
                        messagebox.showerror("Error", 
                                           "Please enter a positive number or 'ALL'")
                        return
                except ValueError:
                    messagebox.showerror("Error", 
                                       "Invalid input. Enter a number or 'ALL'")
                    return
                    
            with self.operation_lock:
                self.current_operation = 'delete_message'
                
            self.delete_message_event.clear()
            self.send_message(Operations.DELETE_MESSAGE, 
                            [self.username, delete_info.upper()])
            dialog.destroy()
            
        ttk.Button(dialog, text="Delete", command=delete_messages).pack(pady=10)
        
    def confirm_delete_account(self):
        """Show confirmation dialog for account deletion"""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in to delete your account")
            return
            
        if messagebox.askyesno("Confirm Delete", 
                              "Are you sure you want to delete your account? " +
                              "This action cannot be undone."):
            with self.operation_lock:
                self.current_operation = 'delete_account'
                
            self.delete_account_event.clear()
            self.send_message(Operations.DELETE_ACCOUNT, [self.username])
            
    def logout(self):
        """Handle user logout"""
        if not self.username:
            messagebox.showerror("Error", "You are not logged in")
            return
            
        with self.operation_lock:
            self.current_operation = 'logout'
            
        self.logout_event.clear()
        self.send_message(Operations.LOGOUT, [self.username])
        
    def show_create_account_dialog(self):
        """Show dialog for creating a new account"""
        # First dialog for username check
        check_dialog = tk.Toplevel(self.root)
        check_dialog.title("Check Username")
        check_dialog.geometry("300x150")
        
        # Add status label
        self.status_label = ttk.Label(check_dialog, text="")
        self.status_label.pack(pady=5)
        
        ttk.Label(check_dialog, text="Enter username to check:").pack(pady=5)
        username_entry = ttk.Entry(check_dialog)
        username_entry.pack(pady=5)
        
        def check_username():
            username = username_entry.get().strip()
            if not username:
                messagebox.showerror("Error", "Username cannot be empty")
                return
                
            # Ensure we're connected
            if not self.running:
                if not self.connect_to_server():
                    return
            
            # Clear previous status
            self.status_label.config(text="Checking username...")
            
            # Set up for username check
            with self.operation_lock:
                self.current_operation = 'check_username'
            
            self.check_username_event.clear()
            self.account_exists_response = None
            
            # Store username for later use
            self.temp_username = username
            
            # Send the check request
            try:
                self.send_message(Operations.CHECK_USERNAME, [username])
                # Start polling for response
                self.root.after(100, lambda: self.poll_username_check(check_dialog))
            except Exception as e:
                self.status_label.config(text=f"Error: {str(e)}")
                print(f"Error sending message: {e}")
        
        ttk.Button(check_dialog, text="Check Username", command=check_username).pack(pady=10)
        
    def poll_username_check(self, check_dialog):
        """Poll for username check response"""
        try:
            if self.check_username_event.is_set():
                print(f"Response received: {self.account_exists_response}")
                
                if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                    self.status_label.config(text="Username available! Creating account...")
                    check_dialog.destroy()
                    self.show_password_dialog(self.temp_username)
                elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                    self.status_label.config(text="Username already exists!")
                else:
                    self.status_label.config(text="Unexpected response")
                
                with self.operation_lock:
                    self.current_operation = None
            else:
                # Poll again after 100ms
                self.root.after(100, lambda: self.poll_username_check(check_dialog))
        except Exception as e:
            print(f"Error in poll_username_check: {e}")
            self.status_label.config(text=f"Error: {str(e)}")
            
    def show_password_dialog(self, username):
        """Show dialog for entering password after username check"""
        pwd_dialog = tk.Toplevel(self.root)
        pwd_dialog.title("Create Account")
        pwd_dialog.geometry("300x150")
        
        ttk.Label(pwd_dialog, text=f"Username: {username}").pack(pady=5)
        ttk.Label(pwd_dialog, text="Enter Password:").pack(pady=5)
        password_entry = ttk.Entry(pwd_dialog, show="*")
        password_entry.pack(pady=5)
        
        def create_account():
            password = password_entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty")
                return
                
            # Hash the password and create account
            hashed_password = hash_password(password)
            
            with self.operation_lock:
                self.current_operation = 'create_account'
                
            self.create_account_event.clear()
            self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password])
            pwd_dialog.destroy()
            
            # Check the response
            self.root.after(100, self.check_create_account_response)
            
        ttk.Button(pwd_dialog, text="Create Account", command=create_account).pack(pady=10)
        
    def handle_server_response(self, msg_type, payload):
        """Handle server responses"""
        try:
            operation = Operations(msg_type)
            print(f"Received response - Type: {operation}, Payload: {payload}")
            
            if operation == Operations.RECEIVE_CURRENT_MESSAGE:
                self.display_message(f"[New Message from {payload[1]}]: {payload[0]}")
                return
                
            with self.operation_lock:
                current_op = self.current_operation
                print(f"Current operation: {current_op}")
            
            if current_op == 'check_username':
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    print(f"Setting account_exists_response to: {operation}")
                    self.account_exists_response = operation
                    self.check_username_event.set()
            elif current_op == 'create_account':
                self.handle_create_account_response(operation, payload)
            elif current_op == 'login':
                self.handle_login_response(operation, payload)
            elif current_op == 'send_message':
                self.handle_send_message_response(operation, payload)
            elif current_op == 'list_accounts':
                self.handle_list_accounts_response(operation, payload)
            elif current_op == 'view_msgs':
                self.handle_view_messages_response(operation, payload)
            elif current_op == 'delete_message':
                self.handle_delete_message_response(operation, payload)
            elif current_op == 'delete_account':
                self.handle_delete_account_response(operation, payload)
            elif current_op == 'logout':
                self.handle_logout_response(operation, payload)
                
        except Exception as e:
            print(f"Error in handle_server_response: {e}")
            messagebox.showerror("Error", f"Error handling server response: {str(e)}")

        
    def send_message(self, message_type: Operations, payload: list):
        """Send a message to the server"""
        try:
            print(f"Sending message type: {message_type}, payload: {payload}")
            serialized = serialize_custom(message_type, payload)
            print(f"Serialized data length: {len(serialized)}")
            self.sock.sendall(serialized)
            print("Message sent successfully")
        except Exception as e:
            print(f"Error sending message: {e}")
            messagebox.showerror("Error", f"Failed to send message: {str(e)}")
            
    def check_username_response(self, check_dialog):
        """Check username availability response"""
        if self.check_username_event.is_set():
            print("Username check event is set")
            print(f"Account exists response: {self.account_exists_response}")
            
            if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                print("Username is available, showing password dialog")
                check_dialog.destroy()
                self.show_password_dialog(self.temp_username)
            elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                print("Username exists, showing error")
                messagebox.showerror("Error", "Account already exists. Please try a different username.")
            else:
                print(f"Unexpected response: {self.account_exists_response}")
                messagebox.showerror("Error", "Unexpected response from server")
            
            with self.operation_lock:
                self.current_operation = None
                print("Reset current operation")
        else:
            print("Username check event not set, checking again in 100ms")
            self.root.after(100, lambda: self.check_username_response(check_dialog))
            
    def handle_server_response(self, msg_type, payload):
        """Handle server responses"""
        try:
            print(f"\nReceived server response - Type: {msg_type}")
            operation = Operations(msg_type)
            print(f"Converted to operation: {operation}")
            
            if operation == Operations.RECEIVE_CURRENT_MESSAGE:
                self.display_message(f"[New Message from {payload[1]}]: {payload[0]}")
                return
                
            with self.operation_lock:
                current_op = self.current_operation
                print(f"Current operation: {current_op}")
            
            if current_op == 'check_username':
                print("Handling check_username response")
                if operation in (Operations.ACCOUNT_DOES_NOT_EXIST, Operations.ACCOUNT_ALREADY_EXISTS):
                    print(f"Setting account_exists_response to: {operation}")
                    self.account_exists_response = operation
                    print("Setting check_username_event")
                    self.check_username_event.set()
                else:
                    print(f"Unexpected operation for check_username: {operation}")
            elif current_op == 'login':
                self.handle_login_response(operation, payload)
            elif current_op == 'send_message':
                self.handle_send_message_response(operation, payload)
            elif current_op == 'create_account':
                self.handle_create_account_response(operation, payload)
            elif current_op == 'list_accounts':
                self.handle_list_accounts_response(operation, payload)
            elif current_op == 'view_msgs':
                self.handle_view_messages_response(operation, payload)
            elif current_op == 'delete_message':
                self.handle_delete_message_response(operation, payload)
            elif current_op == 'delete_account':
                self.handle_delete_account_response(operation, payload)
            elif current_op == 'logout':
                self.handle_logout_response(operation, payload)
                
        except ValueError as e:
            print(f"Error in handle_server_response: {e}")
            messagebox.showerror("Error", f"Unknown message type: {msg_type}")

    def init_events(self):
        """Initialize all events and responses"""
        print("Initializing events")
        self.check_username_event = threading.Event()
        self.account_exists_response = None
        
        self.login_event = threading.Event()
        self.login_response = None
        
        self.logout_event = threading.Event()
        self.logout_response = None
        
        self.create_account_event = threading.Event()
        self.create_account_response = None
        
        self.list_accounts_event = threading.Event()
        self.list_accounts_response = None
        
        self.send_message_event = threading.Event()
        self.send_message_response = None
        
        self.view_msgs_event = threading.Event()
        self.view_msgs_response = None
        
        self.delete_message_event = threading.Event()
        self.delete_message_response = None
        
        self.delete_account_event = threading.Event()
        self.delete_account_response = None
        print("Events initialized")
        
    def check_username_response(self, check_dialog):
        """Check username availability response"""
        if self.check_username_event.is_set():
            if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                # Username is available, show password dialog
                check_dialog.destroy()
                self.show_password_dialog(self.temp_username)
            elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                messagebox.showerror("Error", "Account already exists")
            
            with self.operation_lock:
                self.current_operation = None
        else:
            # Check again after 100ms
            self.root.after(100, lambda: self.check_username_response(check_dialog))
            
    def show_password_dialog(self, username):
        """Show dialog for entering password after username check"""
        pwd_dialog = tk.Toplevel(self.root)
        pwd_dialog.title("Create Account")
        pwd_dialog.geometry("300x150")
        
        ttk.Label(pwd_dialog, text=f"Username: {username}").pack(pady=5)
        ttk.Label(pwd_dialog, text="Enter Password:").pack(pady=5)
        password_entry = ttk.Entry(pwd_dialog, show="*")
        password_entry.pack(pady=5)
        
        def create_account():
            password = password_entry.get().strip()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty")
                return
                
            # Hash the password and create account
            hashed_password = hash_password(password)
            
            with self.operation_lock:
                self.current_operation = 'create_account'
                
            self.create_account_event.clear()
            self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password])
            pwd_dialog.destroy()
            
            # Check the response
            self.root.after(100, self.check_create_account_response)
            
        ttk.Button(pwd_dialog, text="Create Account", command=create_account).pack(pady=10)
        
    def check_username_response(self, dialog):
        """Check username availability response"""
        if self.check_username_event.is_set():
            if self.account_exists_response == Operations.ACCOUNT_DOES_NOT_EXIST:
                # Username is available, proceed with account creation
                self.create_new_account(self.temp_username, self.temp_password)
                dialog.destroy()
            elif self.account_exists_response == Operations.ACCOUNT_ALREADY_EXISTS:
                messagebox.showerror("Error", "Account already exists")
            
            # Clear temporary storage
            self.temp_password = None
            self.temp_username = None
            
            with self.operation_lock:
                self.current_operation = None
        else:
            # Check again after 100ms
            self.root.after(100, self.check_username_response, dialog)
            
    def create_new_account(self, username, password):
        """Create a new account"""
        hashed_password = hash_password(password)
        
        with self.operation_lock:
            self.current_operation = 'create_account'
            
        self.create_account_event.clear()
        self.send_message(Operations.CREATE_ACCOUNT, [username, hashed_password])
        
        # Use after to check the response
        self.root.after(100, self.check_create_account_response)
        
    def check_create_account_response(self):
        """Check account creation response"""
        if self.create_account_event.is_set():
            if self.create_account_response == Operations.SUCCESS:
                self.show_chat_frame()
                self.status_var.set(f"Logged in as: {self.username}")
                messagebox.showinfo("Success", "Account created successfully")
            
            with self.operation_lock:
                self.current_operation = None
        else:
            # Check again after 100ms
            self.root.after(100, self.check_create_account_response)
            
    def list_accounts(self):
        """Show dialog to list accounts"""
        if not self.username:
            messagebox.showerror("Error", "You must be logged in to list accounts")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("List Accounts")
        dialog.geometry("300x200")
        
        ttk.Label(dialog, 
                 text="Enter username pattern (or * for all):").pack(pady=5)
        pattern_entry = ttk.Entry(dialog)
        pattern_entry.insert(0, "*")
        pattern_entry.pack(pady=5)
        
        result_text = scrolledtext.ScrolledText(dialog, height=8)
        result_text.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        
        def search_accounts():
            pattern = pattern_entry.get().strip()
            if not pattern:
                pattern = "*"
                
            with self.operation_lock:
                self.current_operation = 'list_accounts'
                
            self.list_accounts_event.clear()
            self.send_message(Operations.LIST_ACCOUNTS, [self.username, pattern])
            
            # Store the result text widget reference
            self.list_accounts_result = result_text
            
            # Use after to check the response
            self.root.after(100, self.check_list_accounts_response)
            
        ttk.Button(dialog, text="Search", command=search_accounts).pack(pady=5)
        
    def check_list_accounts_response(self):
        """Check list accounts response"""
        if self.list_accounts_event.is_set():
            if hasattr(self, 'list_accounts_result'):
                if self.list_accounts_response == Operations.SUCCESS:
                    # Update the result text widget
                    self.list_accounts_result.delete('1.0', tk.END)
                    self.list_accounts_result.insert('1.0', self.list_accounts_data)
                delattr(self, 'list_accounts_result')
            
            with self.operation_lock:
                self.current_operation = None
        else:
            # Check again after 100ms
            self.root.after(100, self.check_list_accounts_response)
            
    def recvall(self, n):
        """Helper function to receive n bytes"""
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
        
    def cleanup(self):
        """Clean up resources before closing"""
        if self.running:
            self.running = False
            if self.sock:
                self.sock.close()
                
    def run(self):
        """Start the GUI application"""
        # Set up window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Start the main event loop
        self.root.mainloop()
        
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.cleanup()
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    client = ChatClientGUI(root)
    client.run()