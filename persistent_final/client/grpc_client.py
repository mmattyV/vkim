# grpc_client.py

import grpc                     # Import the gRPC library for RPC communication
import threading                # For concurrent execution (background threads)
import time                     # For sleeping and timing operations
import sys                      # For accessing system-specific parameters and functions
import os                       # For operating system dependent functionalities
import argparse                 # For parsing command-line arguments
import logging                  # For logging messages
logging.basicConfig(level=logging.WARNING)  # Set logging level to WARNING by default

# Add the parent directory to the system path so that modules in the common folder can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the gRPC generated classes for message service
import message_service_pb2
import message_service_pb2_grpc

# Import utility functions and configurations from the common module
from common.hash_utils import hash_password
from common.config import config

class ChatClient:
    """
    gRPC Chat Client that always communicates with the current leader.
    The client checks periodically for leader availability and, if the current leader is terminated,
    it discovers a new leader from the provided replica addresses. When a new leader is discovered,
    the client logs out the current session.
    """
    def __init__(self, host=None, port=None, replicas=None):
        # Set fallback host and port from parameters or default config values.
        self.fallback_host = host if host else config.SERVER_HOST_NAME
        self.fallback_port = port if port else config.PORT
        self.fallback_address = f"{self.fallback_host}:{self.fallback_port}"
        
        # Use provided replica addresses if available; otherwise, start with an empty list.
        self.replica_addresses = replicas if replicas else []
        
        # Initially set the leader address to the fallback address.
        self.leader_address = self.fallback_address
        
        # Establish initial gRPC channel and stub with the current leader address.
        self.update_channel_and_stub(self.leader_address)
        
        # Initialize username and unread message counter.
        self.username = None
        self.number_unread_messages = 0
        
        # Flag to control the running state of the client.
        self.running = True
        
        # Thread handle for receiving messages.
        self.receive_thread = None
        
        # Start a background thread to periodically check for leader changes.
        self.leader_check_thread = threading.Thread(target=self.periodic_leader_check, daemon=True)
        self.leader_check_thread.start()

    def update_channel_and_stub(self, address):
        """
        Update the gRPC channel and stub to use the new leader address.
        """
        self.leader_address = address
        self.channel = grpc.insecure_channel(address)
        self.stub = message_service_pb2_grpc.ChatServiceStub(self.channel)
        logging.debug(f"Connected to leader at {address}")

    def discover_leader(self):
        """
        Iterate over known replica addresses (and fallback) to discover the current leader.
        Returns the first discovered leader address.
        """
        # If replicas are provided, use them; otherwise, use only the fallback address.
        if self.replica_addresses:
            candidate_addresses = list(self.replica_addresses)
        else:
            candidate_addresses = [self.fallback_address]
        
        # Try each candidate address to see if it returns a valid leader.
        for addr in candidate_addresses:
            try:
                # Create a temporary channel and stub to query the candidate.
                channel = grpc.insecure_channel(addr)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                req = message_service_pb2.LeaderRequest()
                # Make the RPC call with a timeout.
                resp = stub.GetLeader(req, timeout=2)
                channel.close()
                # If a valid leader address is returned, log it and return.
                if resp and resp.leader_address:
                    logging.info(f"Discovered leader {resp.leader_address} from {addr}")
                    return resp.leader_address
            except Exception as e:
                logging.debug(f"Leader discovery failed on {addr}: {e}")
        # If no leader is found, return None.
        return None

    def safe_rpc_call(self, func, *args, **kwargs):
        """
        Wrapper for RPC calls that retries when UNAVAILABLE errors occur.
        Returns the function's response if successful or None after several retries.
        """
        retry_count = 0
        while retry_count < 5:
            try:
                # Set a default timeout for the RPC call if not already provided.
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = 5
                return func(*args, **kwargs)
            except grpc.RpcError as e:
                # If the error indicates the service is unavailable, try to recover.
                if e.code() == grpc.StatusCode.UNAVAILABLE:
                    print("RPC call unavailable, retrying...")
                    time.sleep(2)
                    retry_count += 1
                    # Attempt to discover a new leader if available.
                    new_leader = self.discover_leader()
                    if new_leader and new_leader != self.leader_address:
                        # Log out current session and update channel if a new leader is found.
                        logging.debug(f"Leader change detected during RPC call: switching from {self.leader_address} to {new_leader}. Logging out current session.")
                        self.username = None
                        self.channel.close()
                        self.update_channel_and_stub(new_leader)
                    continue
                else:
                    # Re-raise the exception for any other RPC error.
                    raise e
        # After several failed retries, print a failure message and return None.
        print("RPC call failed after several retries.")
        return None

    def periodic_leader_check(self):
        """
        In a background loop, periodically check if the current leader is still valid.
        If not, discover a new leader and update the connection accordingly.
        """
        while self.running:
            time.sleep(10)
            try:
                # Create a request to check the leader status.
                req = message_service_pb2.LeaderRequest()
                # Use the safe RPC call wrapper to get the leader information.
                resp = self.safe_rpc_call(self.stub.GetLeader, req, timeout=2)
                if resp is None or not resp.leader_address:
                    # If no leader is returned, try discovering one.
                    new_leader = self.discover_leader()
                    if new_leader and new_leader != self.leader_address:
                        logging.debug(f"Leader change detected via discovery: {new_leader}. Logging out.")
                        self.username = None
                        self.channel.close()
                        self.update_channel_and_stub(new_leader)
                elif resp.leader_address != self.leader_address:
                    # If the returned leader differs from current, update the connection.
                    logging.debug(f"Leader change detected: {resp.leader_address}. Logging out.")
                    self.username = None
                    self.channel.close()
                    self.update_channel_and_stub(resp.leader_address)
            except Exception as e:
                logging.debug(f"Leader check failed: {e}")
                new_leader = self.discover_leader()
                if new_leader:
                    logging.debug(f"Leader discovered during exception: {new_leader}. Logging out.")
                    self.username = None
                    self.channel.close()
                    self.update_channel_and_stub(new_leader)
                else:
                    # If leader discovery fails, revert back to the fallback address.
                    self.channel.close()
                    self.update_channel_and_stub(self.fallback_address)

    def start_receiving(self):
        """
        Start a background thread to continuously receive chat messages.
        """
        if self.username:
            # Define the receiving function to process incoming messages.
            def receive():
                req = message_service_pb2.UsernameRequest(username=self.username)
                try:
                    # Iterate over the streaming messages from the server.
                    for msg in self.stub.ReceiveMessages(req):
                        print(f"\n[New Message from {msg.sender}]: {msg.content} ({msg.timestamp})")
                except grpc.RpcError as e:
                    logging.debug("Message stream ended:", e)
            # Create and start the daemon thread for receiving messages.
            self.receive_thread = threading.Thread(target=receive, daemon=True)
            self.receive_thread.start()

    def try_create_account(self):
        """
        Handle account creation by prompting the user for username and password,
        checking for existence, and creating an account if it does not exist.
        """
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return
        # Check if the username already exists.
        check_req = message_service_pb2.UsernameRequest(username=username)
        check_resp = self.safe_rpc_call(self.stub.CheckUsername, check_req)
        if check_resp and check_resp.exists:
            print("Account already exists. Please log in.")
            self.log_in()
        else:
            password = input("Enter new password: ").strip()
            if not password:
                print("Password cannot be empty.")
                return
            # Hash the password before sending it to the server.
            hashed_password = hash_password(password)
            create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed_password)
            create_resp = self.safe_rpc_call(self.stub.CreateAccount, create_req)
            if create_resp and create_resp.success:
                self.username = create_resp.username
                self.number_unread_messages = create_resp.unread_count
                print(f"Account created successfully. Logged in as {self.username}.")
                print(f"Unread messages: {self.number_unread_messages}")
                self.start_receiving()
            else:
                print(f"Account creation failed: {create_resp.message if create_resp else 'No response'}")

    def log_in(self):
        """
        Handle user login by prompting for credentials and updating the client state.
        """
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        if not username or not password:
            print("Username and password cannot be empty.")
            return
        hashed_password = hash_password(password)
        login_req = message_service_pb2.LoginRequest(username=username, hashed_password=hashed_password)
        login_resp = self.safe_rpc_call(self.stub.Login, login_req)
        if login_resp and login_resp.success:
            self.username = login_resp.username
            self.number_unread_messages = login_resp.unread_count
            print(f"Logged in as {self.username}.")
            print(f"Unread messages: {self.number_unread_messages}")
            self.start_receiving()
        else:
            print(f"Login failed: {login_resp.message if login_resp else 'No response'}")

    def list_accounts(self):
        """
        List accounts matching a provided username pattern.
        """
        if not self.username:
            print("You must be logged in to list accounts.")
            return
        pattern = input("Enter a username pattern (default '*'): ").strip()
        if pattern == "":
            pattern = "*"
        req = message_service_pb2.ListAccountsRequest(username=self.username, pattern=pattern)
        resp = self.safe_rpc_call(self.stub.ListAccounts, req)
        if resp and resp.success:
            print("Matching accounts:")
            for account in resp.accounts:
                print(account)
            print(resp.message)
        else:
            print(f"Failed to list accounts: {resp.message if resp else 'No response'}")

    def send_chat_message(self):
        """
        Send a chat message to a specified recipient.
        """
        if not self.username:
            print("You must be logged in to send messages.")
            return
        recipient = input("Enter recipient username: ").strip()
        message = input("Enter message: ").strip()
        if not recipient or not message:
            print("Recipient and message cannot be empty.")
            return
        req = message_service_pb2.SendMessageRequest(sender=self.username, recipient=recipient, content=message)
        resp = self.safe_rpc_call(self.stub.SendMessage, req)
        print(resp.message if resp else "No response")

    def view_messages(self):
        """
        Retrieve and display a specified number of chat messages.
        """
        if not self.username:
            print("You must be logged in to view messages.")
            return
        count_str = input("Enter number of messages to retrieve: ").strip()
        try:
            count = int(count_str)
        except ValueError:
            print("Invalid number.")
            return
        req = message_service_pb2.ViewMessagesRequest(username=self.username, count=count)
        resp = self.safe_rpc_call(self.stub.ViewMessages, req)
        if resp and resp.success:
            print(resp.message)
            for msg in resp.messages:
                print(f"From {msg.sender}: {msg.content} (at {msg.timestamp})")
        else:
            print(f"Failed to view messages: {resp.message if resp else 'No response'}")

    def delete_messages(self):
        """
        Delete messages based on user input ('ALL' or a specific number).
        """
        if not self.username:
            print("You must be logged in to delete messages.")
            return
        delete_info = input("Enter 'ALL' or number of messages to delete: ").strip()
        if not delete_info:
            print("Delete info cannot be empty.")
            return
        req = message_service_pb2.DeleteMessagesRequest(username=self.username, delete_info=delete_info.upper())
        resp = self.safe_rpc_call(self.stub.DeleteMessages, req)
        print(resp.message if resp else "No response")

    def delete_account(self):
        """
        Delete the currently logged-in user's account after confirmation.
        """
        if not self.username:
            print("You must be logged in to delete your account.")
            return
        confirmation = input("Are you sure you want to delete your account? (yes/no): ").strip().lower()
        if confirmation != "yes":
            print("Account deletion cancelled.")
            return
        req = message_service_pb2.UsernameRequest(username=self.username)
        resp = self.safe_rpc_call(self.stub.DeleteAccount, req)
        if resp and resp.success:
            print(resp.message)
            self.username = None
        else:
            print(f"Failed to delete account: {resp.message if resp else 'No response'}")

    def logout(self):
        """
        Log out the current user.
        """
        if not self.username:
            print("You are not logged in.")
            return
        req = message_service_pb2.LogoutRequest(username=self.username)
        resp = self.safe_rpc_call(self.stub.Logout, req)
        if resp and resp.success:
            print(resp.message)
            self.username = None
        else:
            print(f"Logout failed: {resp.message if resp else 'No response'}")

    def run(self):
        """
        Main loop of the client that prompts the user for operations until exit.
        """
        while self.running:
            print("\nChoose an operation:")
            # Display options based on whether the user is logged in.
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
                # Operations for users not logged in.
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
                # Operations for logged-in users.
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

    # NOTE: The try_create_account method is repeated here by mistake.
    # The duplicate implementation is identical to the one above.
    def try_create_account(self):
        """
        Duplicate of the account creation method (should ideally be removed if not needed).
        """
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return
        check_req = message_service_pb2.UsernameRequest(username=username)
        check_resp = self.safe_rpc_call(self.stub.CheckUsername, check_req)
        if check_resp and check_resp.exists:
            print("Account already exists. Please log in.")
            self.log_in()
        else:
            password = input("Enter new password: ").strip()
            if not password:
                print("Password cannot be empty.")
                return
            hashed_password = hash_password(password)
            create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed_password)
            create_resp = self.safe_rpc_call(self.stub.CreateAccount, create_req)
            if create_resp and create_resp.success:
                self.username = create_resp.username
                self.number_unread_messages = create_resp.unread_count
                print(f"Account created successfully. Logged in as {self.username}.")
                print(f"Unread messages: {self.number_unread_messages}")
                self.start_receiving()
            else:
                print(f"Account creation failed: {create_resp.message if create_resp else 'No response'}")

if __name__ == "__main__":
    # Parse command-line arguments for host, port, and replica addresses.
    parser = argparse.ArgumentParser(description="gRPC Chat Client (Leader-Aware)")
    parser.add_argument('--host', type=str, default=None, help='Fallback server hostname (default from config)')
    parser.add_argument('--port', type=int, default=50051, help='Fallback server port (default 50051)')
    parser.add_argument('--replicas', type=str, default=None, help='Comma-separated list of replica addresses (host:port) for leader discovery')
    args = parser.parse_args()
    # Split the replicas argument into a list if provided.
    replicas = [addr.strip() for addr in args.replicas.split(",")] if args.replicas else []
    
    # Create an instance of ChatClient with the provided or default parameters.
    client = ChatClient(host=args.host, port=args.port, replicas=replicas)
    # Run the client application.
    client.run()