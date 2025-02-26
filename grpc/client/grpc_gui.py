import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog
import threading
import argparse
import os
import sys
import grpc

# Add parent directory to path so that common modules are accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import message_service_pb2
import message_service_pb2_grpc
from common.hash_utils import hash_password
from common.config import config  # Assumes config defines SERVER_HOST_NAME and PORT

class ChatClient:
    """
    gRPC Chat Client that communicates with the server using RPC calls.
    """
    def __init__(self, host=None, port=None):
        self.server_host = host if host else config.SERVER_HOST_NAME
        self.server_port = port if port else config.PORT
        self.channel = grpc.insecure_channel(f"{self.server_host}:{self.server_port}")
        self.stub = message_service_pb2_grpc.ChatServiceStub(self.channel)
        self.username = None
        self.number_unread_messages = 0
        self.receive_thread = None

    def start_receiving(self, callback):
        """
        Start a background thread that receives streaming messages from the server.
        The callback function (provided by the GUI) is called for every new message.
        """
        if self.username:
            def receive():
                request = message_service_pb2.UsernameRequest(username=self.username)
                try:
                    for msg in self.stub.ReceiveMessages(request):
                        # Pass the formatted message to the callback
                        callback(f"[New Message from {msg.sender}]: {msg.content} ({msg.timestamp})")
                except grpc.RpcError as e:
                    callback("Message stream ended.")
            self.receive_thread = threading.Thread(target=receive, daemon=True)
            self.receive_thread.start()

class ChatClientGUI:
    """
    GUI for the gRPC Chat Client.
    Provides a login/create account screen and, once authenticated,
    a main chat window with options to send messages, list accounts,
    view messages, delete messages/account, and log out.
    """
    def __init__(self, root, host=None, port=None):
        self.root = root
        self.root.title("gRPC Chat Client")
        self.root.geometry("600x500")
        self.client = ChatClient(host, port)
        self.create_widgets()

    def create_widgets(self):
        # Create two main frames: one for login and one for chatting.
        self.login_frame = ttk.Frame(self.root)
        self.chat_frame = ttk.Frame(self.root)

        # ----- Login Frame -----
        ttk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)
        ttk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)
        ttk.Button(self.login_frame, text="Login", command=self.handle_login).pack(pady=10)
        ttk.Button(self.login_frame, text="Create Account", command=self.handle_create_account).pack(pady=5)

        # ----- Chat Frame -----
        # Scrolled text area for displaying messages.
        self.message_display = scrolledtext.ScrolledText(self.chat_frame, state='disabled', wrap=tk.WORD)
        self.message_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        # Entry for recipient username.
        self.recipient_entry = ttk.Entry(self.chat_frame)
        self.recipient_entry.pack(fill=tk.X, padx=5, pady=5)
        self.recipient_entry.insert(0, "Recipient Username")
        # Entry for composing a message.
        self.message_input = ttk.Entry(self.chat_frame)
        self.message_input.pack(fill=tk.X, padx=5, pady=5)
        # Send button.
        ttk.Button(self.chat_frame, text="Send Message", command=self.send_message).pack(pady=5)
        # A frame to hold additional operation buttons.
        button_frame = ttk.Frame(self.chat_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(button_frame, text="List Accounts", command=self.list_accounts).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Messages", command=self.view_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Messages", command=self.delete_messages).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Account", command=self.delete_account).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Logout", command=self.logout).pack(side=tk.LEFT, padx=5)

        # Initially show the login frame.
        self.login_frame.pack(expand=True, fill=tk.BOTH)

    def display_message(self, message):
        """Append a message (with newline) to the display area."""
        self.message_display.configure(state='normal')
        self.message_display.insert(tk.END, f"{message}\n")
        self.message_display.see(tk.END)
        self.message_display.configure(state='disabled')

    def handle_login(self):
        """Handle login by reading credentials and calling the Login RPC."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        hashed = hash_password(password)
        login_req = message_service_pb2.LoginRequest(username=username, hashed_password=hashed)
        try:
            resp = self.client.stub.Login(login_req)
            if resp.success:
                self.client.username = resp.username
                self.client.number_unread_messages = resp.unread_count
                self.display_message(f"Logged in as {resp.username} ({resp.unread_count} unread messages)")
                # Start receiving real-time messages.
                self.client.start_receiving(self.display_message)
                self.login_frame.forget()
                self.chat_frame.pack(expand=True, fill=tk.BOTH)
            else:
                messagebox.showerror("Login Failed", resp.message)
        except Exception as e:
            messagebox.showerror("Error", f"Login error: {str(e)}")

    def handle_create_account(self):
        """Handle account creation by checking availability and then calling CreateAccount RPC."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return
        # Check if account exists.
        check_req = message_service_pb2.UsernameRequest(username=username)
        try:
            check_resp = self.client.stub.CheckUsername(check_req)
            if check_resp.exists:
                messagebox.showerror("Error", "Account already exists. Please log in.")
                return
            else:
                hashed = hash_password(password)
                create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed)
                create_resp = self.client.stub.CreateAccount(create_req)
                if create_resp.success:
                    self.client.username = create_resp.username
                    self.client.number_unread_messages = create_resp.unread_count
                    self.display_message(f"Account created and logged in as {create_resp.username} ({create_resp.unread_count} unread messages)")
                    self.client.start_receiving(self.display_message)
                    self.login_frame.forget()
                    self.chat_frame.pack(expand=True, fill=tk.BOTH)
                else:
                    messagebox.showerror("Error", create_resp.message)
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
            messagebox.showerror("Error", "Recipient and message cannot be empty.")
            return
        send_req = message_service_pb2.SendMessageRequest(
            sender=self.client.username,
            recipient=recipient,
            content=msg_text
        )
        try:
            resp = self.client.stub.SendMessage(send_req)
            self.display_message(resp.message)
            self.message_input.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Send message error: {str(e)}")

    def list_accounts(self):
        """Call the ListAccounts RPC and display the matching account names."""
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
            resp = self.client.stub.ListAccounts(list_req)
            if resp.success:
                accounts = "\n".join(resp.accounts)
                self.display_message(f"Accounts:\n{accounts}\n{resp.message}")
            else:
                messagebox.showerror("Error", resp.message)
        except Exception as e:
            messagebox.showerror("Error", f"List accounts error: {str(e)}")

    def view_messages(self):
        """Call the ViewMessages RPC to retrieve undelivered messages and display them."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to view messages.")
            return
        count_str = simpledialog.askstring("View Messages", "Enter number of messages to retrieve:")
        try:
            count = int(count_str)
        except:
            messagebox.showerror("Error", "Invalid number.")
            return
        view_req = message_service_pb2.ViewMessagesRequest(username=self.client.username, count=count)
        try:
            resp = self.client.stub.ViewMessages(view_req)
            if resp.success:
                for msg in resp.messages:
                    self.display_message(f"From {msg.sender}: {msg.content} (at {msg.timestamp})")
                self.display_message(resp.message)
            else:
                messagebox.showerror("Error", resp.message)
        except Exception as e:
            messagebox.showerror("Error", f"View messages error: {str(e)}")

    def delete_messages(self):
        """Call the DeleteMessages RPC to remove messages and display the server response."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to delete messages.")
            return
        delete_info = simpledialog.askstring("Delete Messages", "Enter 'ALL' or number of messages to delete:")
        if not delete_info:
            return
        delete_req = message_service_pb2.DeleteMessagesRequest(username=self.client.username, delete_info=delete_info.upper())
        try:
            resp = self.client.stub.DeleteMessages(delete_req)
            self.display_message(resp.message)
        except Exception as e:
            messagebox.showerror("Error", f"Delete messages error: {str(e)}")

    def delete_account(self):
        """Call the DeleteAccount RPC to delete the current account."""
        if not self.client.username:
            messagebox.showerror("Error", "You must be logged in to delete your account.")
            return
        if messagebox.askyesno("Delete Account", "Are you sure you want to delete your account?"):
            del_req = message_service_pb2.UsernameRequest(username=self.client.username)
            try:
                resp = self.client.stub.DeleteAccount(del_req)
                if resp.success:
                    self.display_message(resp.message)
                    self.client.username = None
                    self.chat_frame.forget()
                    self.login_frame.pack(expand=True, fill=tk.BOTH)
                else:
                    messagebox.showerror("Error", resp.message)
            except Exception as e:
                messagebox.showerror("Error", f"Delete account error: {str(e)}")

    def logout(self):
        """Call the Logout RPC to log out the current user and switch back to the login view."""
        if not self.client.username:
            messagebox.showerror("Error", "You are not logged in.")
            return
        logout_req = message_service_pb2.LogoutRequest(username=self.client.username)
        try:
            resp = self.client.stub.Logout(logout_req)
            if resp.success:
                self.display_message(resp.message)
                self.client.username = None
                self.chat_frame.forget()
                self.login_frame.pack(expand=True, fill=tk.BOTH)
            else:
                messagebox.showerror("Error", resp.message)
        except Exception as e:
            messagebox.showerror("Error", f"Logout error: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="gRPC Chat Client GUI")
    parser.add_argument('--host', type=str, default=None, help='Server hostname (default from config)')
    parser.add_argument('--port', type=int, default=50051, help='Server port (default 50051)')
    args = parser.parse_args()

    root = tk.Tk()
    app = ChatClientGUI(root, host=args.host, port=args.port)
    root.mainloop()

if __name__ == "__main__":
    main()