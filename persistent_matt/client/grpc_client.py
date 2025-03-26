# grpc_client.py
import grpc
import threading
import time
import sys
import os
import argparse
import logging
logging.basicConfig(level=logging.WARNING)

# Add parent directory to path so that common modules are accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import message_service_pb2
import message_service_pb2_grpc

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
        self.fallback_host = host if host else config.SERVER_HOST_NAME
        self.fallback_port = port if port else config.PORT
        self.fallback_address = f"{self.fallback_host}:{self.fallback_port}"
        # Use provided replica addresses (a list) if any.
        self.replica_addresses = replicas if replicas else []
        self.leader_address = self.fallback_address
        self.update_channel_and_stub(self.leader_address)
        self.username = None
        self.number_unread_messages = 0
        self.running = True
        self.receive_thread = None
        # Start background thread to periodically check for leader changes.
        self.leader_check_thread = threading.Thread(target=self.periodic_leader_check, daemon=True)
        self.leader_check_thread.start()

    def update_channel_and_stub(self, address):
        self.leader_address = address
        self.channel = grpc.insecure_channel(address)
        self.stub = message_service_pb2_grpc.ChatServiceStub(self.channel)
        logging.debug(f"Connected to leader at {address}")

    def discover_leader(self):
        """
        Iterate over known replica addresses (if provided). If provided, use them exclusively.
        Returns the first discovered leader address.
        """
        if self.replica_addresses:
            candidate_addresses = list(self.replica_addresses)
        else:
            candidate_addresses = [self.fallback_address]
        for addr in candidate_addresses:
            try:
                channel = grpc.insecure_channel(addr)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                req = message_service_pb2.LeaderRequest()
                resp = stub.GetLeader(req, timeout=2)
                channel.close()
                if resp and resp.leader_address:
                    logging.info(f"Discovered leader {resp.leader_address} from {addr}")
                    return resp.leader_address
            except Exception as e:
                # Log at DEBUG level so these warnings are suppressed
                logging.debug(f"Leader discovery failed on {addr}: {e}")
        return None

    def safe_rpc_call(self, func, *args, **kwargs):
        """
        Wrapper for RPC calls that retries if UNAVAILABLE errors are encountered.
        If after retries the call still fails, it returns None.
        """
        retry_count = 0
        while retry_count < 5:
            try:
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = 5
                return func(*args, **kwargs)
            except grpc.RpcError as e:
                if e.code() == grpc.StatusCode.UNAVAILABLE:
                    logging.debug("RPC call unavailable, retrying...")
                    time.sleep(2)
                    retry_count += 1
                    new_leader = self.discover_leader()
                    if new_leader and new_leader != self.leader_address:
                        # If a new leader is discovered, force logout and update channel.
                        logging.debug(f"Leader change detected during RPC call: switching from {self.leader_address} to {new_leader}. Logging out current session.")
                        self.username = None
                        self.channel.close()
                        self.update_channel_and_stub(new_leader)
                    continue
                else:
                    raise e
        logging.debug("RPC call failed after several retries.")
        return None

    def periodic_leader_check(self):
        """
        Periodically check the current leader. If the current leader becomes unavailable,
        attempt to discover a new leader. If a new leader is found, update the channel and force logout.
        """
        while self.running:
            time.sleep(10)
            try:
                req = message_service_pb2.LeaderRequest()
                resp = self.safe_rpc_call(self.stub.GetLeader, req, timeout=2)
                if resp is None or not resp.leader_address:
                    new_leader = self.discover_leader()
                    if new_leader and new_leader != self.leader_address:
                        logging.debug(f"Leader change detected via discovery: {new_leader}. Logging out.")
                        self.username = None
                        self.channel.close()
                        self.update_channel_and_stub(new_leader)
                elif resp.leader_address != self.leader_address:
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
                    # If no leader can be discovered, fallback
                    self.channel.close()
                    self.update_channel_and_stub(self.fallback_address)

    def start_receiving(self):
        if self.username:
            def receive():
                req = message_service_pb2.UsernameRequest(username=self.username)
                try:
                    for msg in self.stub.ReceiveMessages(req):
                        logging.debug(f"\n[New Message from {msg.sender}]: {msg.content} ({msg.timestamp})")
                except grpc.RpcError as e:
                    logging.debug("Message stream ended:", e)
            self.receive_thread = threading.Thread(target=receive, daemon=True)
            self.receive_thread.start()

    def try_create_account(self):
        username = input("Enter username: ").strip()
        if not username:
            logging.debug("Username cannot be empty.")
            return
        check_req = message_service_pb2.UsernameRequest(username=username)
        check_resp = self.safe_rpc_call(self.stub.CheckUsername, check_req)
        if check_resp and check_resp.exists:
            logging.debug("Account already exists. Please log in.")
            self.log_in()
        else:
            password = input("Enter new password: ").strip()
            if not password:
                logging.debug("Password cannot be empty.")
                return
            hashed_password = hash_password(password)
            create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed_password)
            create_resp = self.safe_rpc_call(self.stub.CreateAccount, create_req)
            if create_resp and create_resp.success:
                self.username = create_resp.username
                self.number_unread_messages = create_resp.unread_count
                logging.debug(f"Account created successfully. Logged in as {self.username}.")
                logging.debug(f"Unread messages: {self.number_unread_messages}")
                self.start_receiving()
            else:
                logging.debug(f"Account creation failed: {create_resp.message if create_resp else 'No response'}")

    def log_in(self):
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        if not username or not password:
            logging.debug("Username and password cannot be empty.")
            return
        hashed_password = hash_password(password)
        login_req = message_service_pb2.LoginRequest(username=username, hashed_password=hashed_password)
        login_resp = self.safe_rpc_call(self.stub.Login, login_req)
        if login_resp and login_resp.success:
            self.username = login_resp.username
            self.number_unread_messages = login_resp.unread_count
            logging.debug(f"Logged in as {self.username}.")
            logging.debug(f"Unread messages: {self.number_unread_messages}")
            self.start_receiving()
        else:
            logging.debug(f"Login failed: {login_resp.message if login_resp else 'No response'}")

    def list_accounts(self):
        if not self.username:
            logging.debug("You must be logged in to list accounts.")
            return
        pattern = input("Enter a username pattern (default '*'): ").strip()
        if pattern == "":
            pattern = "*"
        req = message_service_pb2.ListAccountsRequest(username=self.username, pattern=pattern)
        resp = self.safe_rpc_call(self.stub.ListAccounts, req)
        if resp and resp.success:
            logging.debug("Matching accounts:")
            for account in resp.accounts:
                logging.debug(account)
            logging.debug(resp.message)
        else:
            logging.debug(f"Failed to list accounts: {resp.message if resp else 'No response'}")

    def send_chat_message(self):
        if not self.username:
            logging.debug("You must be logged in to send messages.")
            return
        recipient = input("Enter recipient username: ").strip()
        message = input("Enter message: ").strip()
        if not recipient or not message:
            logging.debug("Recipient and message cannot be empty.")
            return
        req = message_service_pb2.SendMessageRequest(sender=self.username, recipient=recipient, content=message)
        resp = self.safe_rpc_call(self.stub.SendMessage, req)
        logging.debug(resp.message if resp else "No response")

    def view_messages(self):
        if not self.username:
            logging.debug("You must be logged in to view messages.")
            return
        count_str = input("Enter number of messages to retrieve: ").strip()
        try:
            count = int(count_str)
        except ValueError:
            logging.debug("Invalid number.")
            return
        req = message_service_pb2.ViewMessagesRequest(username=self.username, count=count)
        resp = self.safe_rpc_call(self.stub.ViewMessages, req)
        if resp and resp.success:
            logging.debug(resp.message)
            for msg in resp.messages:
                logging.debug(f"From {msg.sender}: {msg.content} (at {msg.timestamp})")
        else:
            logging.debug(f"Failed to view messages: {resp.message if resp else 'No response'}")

    def delete_messages(self):
        if not self.username:
            logging.debug("You must be logged in to delete messages.")
            return
        delete_info = input("Enter 'ALL' or number of messages to delete: ").strip()
        if not delete_info:
            logging.debug("Delete info cannot be empty.")
            return
        req = message_service_pb2.DeleteMessagesRequest(username=self.username, delete_info=delete_info.upper())
        resp = self.safe_rpc_call(self.stub.DeleteMessages, req)
        logging.debug(resp.message if resp else "No response")

    def delete_account(self):
        if not self.username:
            logging.debug("You must be logged in to delete your account.")
            return
        confirmation = input("Are you sure you want to delete your account? (yes/no): ").strip().lower()
        if confirmation != "yes":
            logging.debug("Account deletion cancelled.")
            return
        req = message_service_pb2.UsernameRequest(username=self.username)
        resp = self.safe_rpc_call(self.stub.DeleteAccount, req)
        if resp and resp.success:
            logging.debug(resp.message)
            self.username = None
        else:
            logging.debug(f"Failed to delete account: {resp.message if resp else 'No response'}")

    def logout(self):
        if not self.username:
            logging.debug("You are not logged in.")
            return
        req = message_service_pb2.LogoutRequest(username=self.username)
        resp = self.safe_rpc_call(self.stub.Logout, req)
        if resp and resp.success:
            logging.debug(resp.message)
            self.username = None
        else:
            logging.debug(f"Logout failed: {resp.message if resp else 'No response'}")

    def run(self):
        while self.running:
            logging.debug("\nChoose an operation:")
            if not self.username:
                logging.debug("1. Create Account")
                logging.debug("2. Log In")
                logging.debug("3. Exit")
            else:
                logging.debug("1. List Accounts")
                logging.debug("2. Send Message")
                logging.debug("3. View Messages")
                logging.debug("4. Delete Messages")
                logging.debug("5. Delete Account")
                logging.debug("6. Logout")
                logging.debug("7. Exit")
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
                    logging.debug("Invalid choice.")
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
                    logging.debug("Invalid choice.")
        logging.debug("Exiting client...")
        self.channel.close()

    def try_create_account(self):
        username = input("Enter username: ").strip()
        if not username:
            logging.debug("Username cannot be empty.")
            return
        check_req = message_service_pb2.UsernameRequest(username=username)
        check_resp = self.safe_rpc_call(self.stub.CheckUsername, check_req)
        if check_resp and check_resp.exists:
            logging.debug("Account already exists. Please log in.")
            self.log_in()
        else:
            password = input("Enter new password: ").strip()
            if not password:
                logging.debug("Password cannot be empty.")
                return
            hashed_password = hash_password(password)
            create_req = message_service_pb2.CreateAccountRequest(username=username, hashed_password=hashed_password)
            create_resp = self.safe_rpc_call(self.stub.CreateAccount, create_req)
            if create_resp and create_resp.success:
                self.username = create_resp.username
                self.number_unread_messages = create_resp.unread_count
                logging.debug(f"Account created successfully. Logged in as {self.username}.")
                logging.debug(f"Unread messages: {self.number_unread_messages}")
                self.start_receiving()
            else:
                logging.debug(f"Account creation failed: {create_resp.message if create_resp else 'No response'}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="gRPC Chat Client (Leader-Aware)")
    parser.add_argument('--host', type=str, default=None, help='Fallback server hostname (default from config)')
    parser.add_argument('--port', type=int, default=50051, help='Fallback server port (default 50051)')
    parser.add_argument('--replicas', type=str, default=None, help='Comma-separated list of replica addresses (host:port) for leader discovery')
    args = parser.parse_args()
    replicas = [addr.strip() for addr in args.replicas.split(",")] if args.replicas else []
    client = ChatClient(host=args.host, port=args.port, replicas=replicas)
    client.run()