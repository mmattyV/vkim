import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import argparse
import sys
import os
import grpc
import time
import logging

# Add the parent directory to the system path so that modules in the common folder can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the gRPC generated classes and utilities
import message_service_pb2
import message_service_pb2_grpc
from common.hash_utils import hash_password
from common.config import config

# Import the ChatClient from your original grpc_client.py file.
# (Ensure grpc_client.py is accessible via sys.path.)
from grpc_client import ChatClient

class ChatClientGUI:
    """
    GUI for the gRPC Chat Client.
    This class reuses the backend ChatClient (with leader discovery and safe RPC calls)
    and provides a Tkinter-based interface for login, account creation, messaging, and more.
    
    An automatic check ensures that if the client becomes logged out (i.e. username is None),
    the GUI switches back to the login screen.
    """
    def __init__(self, root, host=None, port=None, replicas=None):
        self.root = root
        self.root.geometry("800x600")
        self.root.title("gRPC Chat Client GUI")
        
        # Create a ChatClient instance from the existing code.
        self.client = ChatClient(host, port, replicas)
        
        # Create the main widgets (login frame and chat frame).
        self.create_widgets()
        
        # Start a periodic update of the unread message counter.
        self.update_unread_counter()
        # Start a periodic check of the logged-in status.
        self.check_logged_in_status()

    def create_widgets(self):
        # ----- Login Frame -----
        self.login_frame = ttk.Frame(self.root)
        self.login_frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        ttk.Button(self.login_frame, text="Login", command=self.handle_login).pack(pady=10)
        ttk.Button(self.login_frame, text="Create Account", command=self.handle_create_account).pack(pady=5)
        
        # ----- Chat Frame -----
        self.chat_frame = ttk.Frame(self.root)
        # Scrolled text area for displaying chat messages.
        self.message_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap=tk.WORD, height=15)
        self.message_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Input frame for recipient and message.
        input_frame = ttk.Frame(self.chat_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(input_frame, text="Recipient:").grid(row=0, column=0, sticky=tk.W, padx=2, pady=2)
        self.recipient_entry = ttk.Entry(input_frame)
        self.recipient_entry.grid(row=0, column=1, sticky=tk.EW, padx=2, pady=2)
        input_frame.columnconfigure(1, weight=1)
        ttk.Label(input_frame, text="Message:").grid(row=1, column=0, sticky=tk.W, padx=2, pady=2)
        self.message_input = ttk.Entry(input_frame)
        self.message_input.grid(row=1, column=1, sticky=tk.EW, padx=2, pady=2)
        
        # Send button.
        ttk.Button(self.chat_frame, text="Send Message", command=self.send_message).pack(pady=5)
        
        # Button frame for additional operations.
        button_frame = ttk.Frame(self.chat_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(button_frame, text="List Accounts", command=self.list_accounts).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Messages", command=self.view_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Messages", command=self.delete_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Account", command=self.delete_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)
        
        # Live unread messages counter.
        self.unread_label = ttk.Label(self.chat_frame, text="Unread Messages: 0", font=("Arial", 10, "italic"))
        self.unread_label.pack(pady=5)

    def update_unread_counter(self):
        """Update the unread message counter and schedule the next update."""
        count = self.client.number_unread_messages
        self.unread_label.config(text=f"Unread Messages: {count}")
        self.root.after(1000, self.update_unread_counter)

    def check_logged_in_status(self):
        """
        Periodically check if the client is logged in.
        If the client is not logged in (i.e. username is None) and the chat frame is visible,
        automatically switch to the login screen.
        """
        if not self.client.username:
            # If the chat frame is currently visible, return to login screen.
            if self.chat_frame.winfo_ismapped():
                self.chat_frame.forget()
                self.login_frame.pack(expand=True, fill=tk.BOTH)
        self.root.after(1000, self.check_logged_in_status)

    def display_message(self, message):
        """Append a chat message to the message display area."""
        self.message_display.configure(state='normal')
        self.message_display.insert(tk.END, f"{message}\n")
        self.message_display.see(tk.END)
        self.message_display.configure(state='disabled')

    def start_receiving(self):
        """
        Start a background thread that receives messages using the client's stub.
        The received messages are passed to display_message.
        """
        def receive():
            req = message_service_pb2.UsernameRequest(username=self.client.username)
            try:
                for msg in self.client.stub.ReceiveMessages(req):
                    self.display_message(f"[New Message from {msg.sender}]: {msg.content} ({msg.timestamp})")
            except grpc.RpcError as e:
                self.display_message("Message stream ended.")
        threading.Thread(target=receive, daemon=True).start()

    def handle_login(self):
        """Handle login by reading credentials from the GUI and calling the Login RPC."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        hashed = hash_password(password)
        login_req = message_service_pb2.LoginRequest(username=username, hashed_password=hashed)
        try:
            # Use the safe_rpc_call from ChatClient to ensure retries and leader discovery.
            resp = self.client.safe_rpc_call(self.client.stub.Login, login_req, timeout=5)
            if resp and resp.success:
                self.client.username = resp.username
                self.client.number_unread_messages = resp.unread_count
                messagebox.showinfo("Login Successful", f"Logged in as {resp.username}")
                self.start_receiving()
                self.login_frame.forget()
                self.chat_frame.pack(expand=True, fill=tk.BOTH)
            else:
                messagebox.showerror("Login Failed", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"Login error: {str(e)}")

    def handle_create_account(self):
        """Handle account creation by reading credentials from the GUI and calling the CreateAccount RPC."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        # First, check if the username exists.
        check_req = message_service_pb2.UsernameRequest(username=username)
        try:
            check_resp = self.client.safe_rpc_call(self.client.stub.CheckUsername, check_req, timeout=5)
            if check_resp and check_resp.exists:
                messagebox.showerror("Error", "Account already exists. Please log in.")
                return
            else:
                hashed = hash_password(password)
                create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed)
                create_resp = self.client.safe_rpc_call(self.client.stub.CreateAccount, create_req, timeout=5)
                if create_resp and create_resp.success:
                    self.client.username = create_resp.username
                    self.client.number_unread_messages = create_resp.unread_count
                    messagebox.showinfo("Account Created", f"Account created and logged in as {create_resp.username}")
                    self.start_receiving()
                    self.login_frame.forget()
                    self.chat_frame.pack(expand=True, fill=tk.BOTH)
                else:
                    messagebox.showerror("Error", create_resp.message if create_resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"Create account error: {str(e)}")

    def send_message(self):
        """Send a chat message using the SendMessage RPC."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to send messages.")
            return
        recipient = self.recipient_entry.get().strip()
        msg_text = self.message_input.get().strip()
        if not recipient or not msg_text:
            messagebox.showerror("Error", "Both recipient and message must be provided.")
            return
        send_req = message_service_pb2.SendMessageRequest(
            sender=self.client.username,
            recipient=recipient,
            content=msg_text
        )
        try:
            resp = self.client.safe_rpc_call(self.client.stub.SendMessage, send_req, timeout=5)
            messagebox.showinfo("Send Message", resp.message if resp else "No response")
            self.message_input.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Send message error: {str(e)}")

    def list_accounts(self):
        """Call the ListAccounts RPC and display matching accounts."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to list accounts.")
            return
        pattern = simpledialog.askstring("List Accounts", "Enter username pattern (or leave blank for '*'):")
        if pattern is None:
            return
        if pattern.strip() == "":
            pattern = "*"
        list_req = message_service_pb2.ListAccountsRequest(username=self.client.username, pattern=pattern)
        try:
            resp = self.client.safe_rpc_call(self.client.stub.ListAccounts, list_req, timeout=5)
            if resp and resp.success:
                accounts = "\n".join(resp.accounts)
                messagebox.showinfo("Accounts", f"Accounts:\n{accounts}\n{resp.message}")
            else:
                messagebox.showerror("Error", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"List accounts error: {str(e)}")

    def view_messages(self):
        """
        Call the ViewMessages RPC to retrieve messages and display them.
        After viewing, the unread messages counter is reset.
        """
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to view messages.")
            return
        count_str = simpledialog.askstring("View Messages", "Enter number of messages to retrieve:")
        try:
            count = int(count_str)
        except Exception:
            messagebox.showerror("Error", "Invalid number.")
            return
        view_req = message_service_pb2.ViewMessagesRequest(username=self.client.username, count=count)
        try:
            resp = self.client.safe_rpc_call(self.client.stub.ViewMessages, view_req, timeout=5)
            if resp and resp.success:
                for msg in resp.messages:
                    self.display_message(f"From {msg.sender}: {msg.content} (at {msg.timestamp})")
                self.display_message(resp.message)
                # Assume that viewing messages resets the unread count.
                self.client.number_unread_messages = 0
            else:
                messagebox.showerror("Error", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"View messages error: {str(e)}")

    def delete_messages(self):
        """Call the DeleteMessages RPC and show the server response."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to delete messages.")
            return
        delete_info = simpledialog.askstring("Delete Messages", "Enter 'ALL' or number of messages to delete:")
        if not delete_info:
            return
        delete_req = message_service_pb2.DeleteMessagesRequest(username=self.client.username, delete_info=delete_info.upper())
        try:
            resp = self.client.safe_rpc_call(self.client.stub.DeleteMessages, delete_req, timeout=5)
            messagebox.showinfo("Delete Messages", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"Delete messages error: {str(e)}")

    def delete_account(self):
        """Call the DeleteAccount RPC and handle account deletion."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to delete your account.")
            return
        if not messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?"):
            return
        del_req = message_service_pb2.UsernameRequest(username=self.client.username)
        try:
            resp = self.client.safe_rpc_call(self.client.stub.DeleteAccount, del_req, timeout=5)
            if resp and resp.success:
                messagebox.showinfo("Delete Account", resp.message)
                self.client.username = None
                self.chat_frame.forget()
                self.login_frame.pack(expand=True, fill=tk.BOTH)
            else:
                messagebox.showerror("Error", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"Delete account error: {str(e)}")

    def logout(self):
        """Call the Logout RPC and return to the login screen."""
        if not self.client.username:
            messagebox.showerror("Error", "You are not logged in.")
            return
        logout_req = message_service_pb2.LogoutRequest(username=self.client.username)
        try:
            resp = self.client.safe_rpc_call(self.client.stub.Logout, logout_req, timeout=5)
            if resp and resp.success:
                messagebox.showinfo("Logout", resp.message)
                self.client.username = None
                self.chat_frame.forget()
                self.login_frame.pack(expand=True, fill=tk.BOTH)
            else:
                messagebox.showerror("Error", resp.message if resp else "No response")
        except Exception as e:
            messagebox.showerror("Error", f"Logout error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="gRPC Chat Client GUI")
    parser.add_argument('--host', type=str, default=None, help='Fallback server hostname (default from config)')
    parser.add_argument('--port', type=int, default=50051, help='Fallback server port (default 50051)')
    parser.add_argument('--replicas', type=str, default=None, help='Comma-separated list of replica addresses (host:port) for leader discovery')
    args = parser.parse_args()
    replicas = [addr.strip() for addr in args.replicas.split(",")] if args.replicas else []
    
    root = tk.Tk()
    app = ChatClientGUI(root, host=args.host, port=args.port, replicas=replicas)
    root.mainloop()

if __name__ == "__main__":
    main()