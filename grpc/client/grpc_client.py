import grpc
import threading
import time
import sys
import os
import argparse

# Add parent directory to path so that common modules are accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import generated protobuf modules
import message_service_pb2
import message_service_pb2_grpc

# Import common utilities
from common.hash_utils import hash_password
from common.config import config  # Assumes config defines SERVER_HOST_NAME and PORT

class ChatClient:
    """
    gRPC Chat Client that communicates with the chat server using RPC calls.
    Provides account creation, login, messaging, and account management features.
    """
    def __init__(self, host=None, port=None):
        self.server_host = host if host else config.SERVER_HOST_NAME
        self.server_port = port if port else config.PORT

        # Create a gRPC channel and stub for RPC calls
        self.channel = grpc.insecure_channel(f"{self.server_host}:{self.server_port}")
        self.stub = message_service_pb2_grpc.ChatServiceStub(self.channel)

        self.username = None
        self.number_unread_messages = 0
        self.running = True
        self.receive_thread = None

    def start_receiving(self):
        """
        Start a background thread that calls the streaming RPC to receive
        real-time messages from the server.
        """
        if self.username:
            def receive():
                request = message_service_pb2.UsernameRequest(username=self.username)
                try:
                    for msg in self.stub.ReceiveMessages(request):
                        print(f"\n[New Message from {msg.sender}]: {msg.content} ({msg.timestamp})")
                except grpc.RpcError as e:
                    print("Message stream ended:", e)
            self.receive_thread = threading.Thread(target=receive, daemon=True)
            self.receive_thread.start()

    def try_create_account(self):
        """
        Check if the username exists using the CheckUsername RPC.
        If not, prompt for a password and create a new account via CreateAccount RPC.
        """
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return

        # Check if the account already exists
        check_req = message_service_pb2.UsernameRequest(username=username)
        check_resp = self.stub.CheckUsername(check_req)
        if check_resp.exists:
            print("Account already exists. Please log in.")
            self.log_in()
        else:
            password = input("Enter new password: ").strip()
            if not password:
                print("Password cannot be empty.")
                return
            hashed_password = hash_password(password)
            create_req = message_service_pb2.CreateAccountRequest(
                username=username,
                hashed_password=hashed_password
            )
            create_resp = self.stub.CreateAccount(create_req)
            if create_resp.success:
                self.username = create_resp.username
                self.number_unread_messages = create_resp.unread_count
                print(f"Account created successfully. Logged in as {self.username}.")
                print(f"Unread messages: {self.number_unread_messages}")
                self.start_receiving()
            else:
                print(f"Account creation failed: {create_resp.message}")

    def log_in(self):
        """
        Prompt the user for credentials and call the Login RPC.
        On success, update the client state and start the message stream.
        """
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        if not username or not password:
            print("Username and password cannot be empty.")
            return

        hashed_password = hash_password(password)
        login_req = message_service_pb2.LoginRequest(
            username=username,
            hashed_password=hashed_password
        )
        login_resp = self.stub.Login(login_req)
        if login_resp.success:
            self.username = login_resp.username
            self.number_unread_messages = login_resp.unread_count
            print(f"Logged in as {self.username}.")
            print(f"Unread messages: {self.number_unread_messages}")
            self.start_receiving()
        else:
            print(f"Login failed: {login_resp.message}")

    def list_accounts(self):
        """
        Call the ListAccounts RPC to retrieve accounts matching a username pattern.
        """
        if not self.username:
            print("You must be logged in to list accounts.")
            return

        pattern = input("Enter a username pattern to search for (default '*'): ").strip()
        if pattern == "":
            pattern = "*"

        request = message_service_pb2.ListAccountsRequest(
            username=self.username,
            pattern=pattern
        )
        response = self.stub.ListAccounts(request)
        if response.success:
            print("Matching accounts:")
            for account in response.accounts:
                print(account)
            print(response.message)
        else:
            print(f"Failed to list accounts: {response.message}")

    def send_chat_message(self):
        """
        Send a chat message to another user by calling the SendMessage RPC.
        """
        if not self.username:
            print("You must be logged in to send messages.")
            return

        recipient = input("Enter recipient username: ").strip()
        message = input("Enter message: ").strip()
        if not recipient or not message:
            print("Recipient and message cannot be empty.")
            return

        request = message_service_pb2.SendMessageRequest(
            sender=self.username,
            recipient=recipient,
            content=message
        )
        response = self.stub.SendMessage(request)
        print(response.message)

    def view_messages(self):
        """
        Retrieve undelivered messages by calling the ViewMessages RPC.
        Displays each message along with sender and timestamp.
        """
        if not self.username:
            print("You must be logged in to view messages.")
            return

        count_str = input("Enter the number of messages to retrieve: ").strip()
        try:
            count = int(count_str)
        except ValueError:
            print("Invalid number.")
            return

        request = message_service_pb2.ViewMessagesRequest(
            username=self.username,
            count=count
        )
        response = self.stub.ViewMessages(request)
        if response.success:
            print(response.message)
            for msg in response.messages:
                print(f"From {msg.sender}: {msg.content} (at {msg.timestamp})")
        else:
            print(f"Failed to view messages: {response.message}")

    def delete_messages(self):
        """
        Delete messages using the DeleteMessages RPC.
        The user can delete all messages or a specified number.
        """
        if not self.username:
            print("You must be logged in to delete messages.")
            return

        delete_info = input("Enter 'ALL' to delete all messages or the number of messages to delete: ").strip()
        if not delete_info:
            print("Delete info cannot be empty.")
            return

        request = message_service_pb2.DeleteMessagesRequest(
            username=self.username,
            delete_info=delete_info.upper()
        )
        response = self.stub.DeleteMessages(request)
        print(response.message)

    def delete_account(self):
        """
        Delete the current user's account via the DeleteAccount RPC.
        The account can only be deleted if there are no unread messages.
        """
        if not self.username:
            print("You must be logged in to delete your account.")
            return

        confirmation = input("Are you sure you want to delete your account? (yes/no): ").strip().lower()
        if confirmation != "yes":
            print("Account deletion cancelled.")
            return

        request = message_service_pb2.UsernameRequest(username=self.username)
        response = self.stub.DeleteAccount(request)
        if response.success:
            print(response.message)
            self.username = None
        else:
            print(f"Failed to delete account: {response.message}")

    def logout(self):
        """
        Log out the current user using the Logout RPC.
        """
        if not self.username:
            print("You are not logged in.")
            return

        request = message_service_pb2.LogoutRequest(username=self.username)
        response = self.stub.Logout(request)
        if response.success:
            print(response.message)
            self.username = None
        else:
            print(f"Logout failed: {response.message}")

    def run(self):
        """
        Main client loop. Displays a menu based on whether the user is logged in
        and handles user input to invoke the corresponding RPC calls.
        """
        while self.running:
            print("\nChoose an operation:")
            if not self.username:
                print("1. Create Account")
                print("2. Log In")
                print("3. Exit")
            else:
                print("1. List Accounts")
                print("2. Send Message")
                print("3. View Messages")
                print("4. Delete Messages")
                print("5. Delete Account")
                print("6. Logout")
                print("7. Exit")
            choice = input("Enter choice number: ").strip()
            if not self.username:
                if choice == "1":
                    self.try_create_account()
                elif choice == "2":
                    self.log_in()
                elif choice == "3":
                    self.running = False
                    break
                else:
                    print("Invalid choice.")
            else:
                if choice == "1":
                    self.list_accounts()
                elif choice == "2":
                    self.send_chat_message()
                elif choice == "3":
                    self.view_messages()
                elif choice == "4":
                    self.delete_messages()
                elif choice == "5":
                    self.delete_account()
                elif choice == "6":
                    self.logout()
                elif choice == "7":
                    self.running = False
                    break
                else:
                    print("Invalid choice.")
        print("Exiting client...")
        self.channel.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="gRPC Chat Client Terminal")
    parser.add_argument('--host', type=str, default=None,
                        help='Server hostname (default: defined in config)')
    parser.add_argument('--port', type=int, default=50051,
                        help='Server port (default: 50051)')
    args = parser.parse_args()

    client = ChatClient(host=args.host, port=args.port)
    client.run()