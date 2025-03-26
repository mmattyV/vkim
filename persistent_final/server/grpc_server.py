#!/usr/bin/env python
"""
gRPC Chat Server with Persistence, Replication, and Leader Election.

This module implements the ChatServiceServicer class which handles all gRPC RPCs
for account management, messaging, replication, leader election, and state synchronization.
"""

import os                     # For file and operating system operations
import sys                    # For system-specific parameters and functions
import time                   # For timing functions and sleep operations
import threading              # For running concurrent background tasks
import fnmatch                # For Unix filename pattern matching
import grpc                   # For gRPC server and client operations
import argparse               # For parsing command-line arguments
import json                   # For serializing and deserializing JSON data
import uuid                   # For generating unique IDs for updates
import socket                 # For getting hostname and network-related functions
from concurrent import futures  # For creating thread pool executors
from queue import Queue       # For message queue implementation

# Add the common directory to the system path so that modules from it can be imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import gRPC generated classes for the message service
import message_service_pb2
import message_service_pb2_grpc

# Import common utilities and classes
from common.user import User
from common.hash_utils import hash_password
from common.persistence import load_state, save_state

class ChatServiceServicer(message_service_pb2_grpc.ChatServiceServicer):
    """
    Chat Service implementation that provides persistence, replication,
    leader election, and state synchronization for a chat application.
    """

    def __init__(self, port, replica_addresses=None):
        """
        Initialize the ChatServiceServicer instance.

        Loads persisted state from disk and initializes data structures for users,
        message queues, replication log, and active user streams. It also sets up
        the server's own address and determines leadership. Finally, it starts
        the background leader election loop.

        Args:
            port (int): The port number on which the server will listen.
            replica_addresses (list, optional): List of replica addresses (host:port)
                                                for replication and leader election.
        """
        self.my_port = port  # Save the server port for persistence purposes

        # Load persisted state from disk using the server's port as an identifier.
        state = load_state(self.my_port)
        self.users = state.get("users", {})  # Dictionary of users, keyed by username
        mq_data = state.get("message_queues", {})
        self.message_queues = {}
        # Convert stored message lists to Queue objects for each user.
        for username, messages in mq_data.items():
            q = Queue()
            for msg in messages:
                q.put(msg)
            self.message_queues[username] = q
        # Load replication log (a set of update IDs) to prevent duplicate application.
        self.replication_log = state.get("replication_log", set())

        # Lock to ensure thread-safe operations on shared state.
        self.user_lock = threading.Lock()
        # Dictionary mapping usernames to their stream contexts (active connections).
        self.active_users = {}
        # List of other replica addresses.
        self.replica_addresses = replica_addresses if replica_addresses else []

        # Determine the server's own address using its hostname and provided port.
        self.my_address = f"{socket.gethostname()}:{port}"

        # Initially assume this node is the leader.
        self.current_leader = self.my_address
        self.is_leader = True

        # Start a background thread to continuously run the leader election loop.
        threading.Thread(target=self.run_leader_election_loop, daemon=True).start()

        print(f"Chat Service initialized on {self.my_address} with persistence, replication, and leader election.")

        # If this node is not the leader, resynchronize state from the current leader.
        if not self.is_leader:
            self.resync_state()

    def persist_state(self):
        """
        Persist the current state to disk.

        Converts non-pickleable objects (like Queues) into basic types so that the state
        can be saved using pickle. The state includes users, message queues, and the replication log.
        """
        # Convert each message queue to a list for serialization.
        mq = {username: list(q.queue) for username, q in self.message_queues.items()}
        state = {
            "users": self.users,
            "message_queues": mq,
            "replication_log": self.replication_log
        }
        save_state(state, self.my_port)

    def replicate_update(self, operation, data, update_id):
        """
        Replicate an update operation to all replica nodes.

        Args:
            operation (str): The operation name (e.g., "CreateAccount", "SendMessage").
            data (str): JSON-serialized update details.
            update_id (str): Unique update identifier to prevent duplicate application.
        """
        req = message_service_pb2.ReplicationRequest(
            operation=operation,
            data=data,
            update_id=update_id
        )
        # Send the replication request to each replica node.
        for addr in self.replica_addresses:
            try:
                channel = grpc.insecure_channel(addr)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                response = stub.ReplicateOperation(req)
                print(f"Replicated update to {addr}: {response.message}")
                channel.close()
            except Exception as e:
                print(f"Replication to {addr} failed: {e}")

    def resync_state(self):
        """
        Synchronize the state of this node with the current leader.

        Uses the SyncState RPC to retrieve the current state as a JSON string and then
        updates the in-memory state accordingly.
        """
        try:
            channel = grpc.insecure_channel(self.current_leader)
            stub = message_service_pb2_grpc.ChatServiceStub(channel)
            req = message_service_pb2.SyncStateRequest()
            resp = stub.SyncState(req, timeout=5)
            channel.close()
            if resp and resp.state_json:
                new_state = json.loads(resp.state_json)
                with self.user_lock:
                    self.users = new_state.get("users", {})
                    mq_data = new_state.get("message_queues", {})
                    self.message_queues = {}
                    # Reconstruct Queue objects from the received lists.
                    for username, messages in mq_data.items():
                        q = Queue()
                        for msg in messages:
                            q.put(msg)
                        self.message_queues[username] = q
                    self.replication_log = set(new_state.get("replication_log", []))
                print("State synchronized with leader.")
            else:
                print("No state received from leader.")
        except Exception as e:
            print(f"Failed to resync state: {e}")

    # --- Leader Election and Heartbeat RPCs ---

    def Ping(self, request, context):
        """
        Respond to a ping request with a Pong message.

        Args:
            request: The PingRequest message.
            context: gRPC context.

        Returns:
            PingResponse: Contains a pong message and sender's address.
        """
        return message_service_pb2.PingResponse(
            message=f"Pong from {self.my_address}",
            sender_id=self.my_address
        )

    def GetLeader(self, request, context):
        """
        Return the address of the current leader.

        Args:
            request: The LeaderRequest message.
            context: gRPC context.

        Returns:
            LeaderResponse: Contains the current leader's address.
        """
        return message_service_pb2.LeaderResponse(
            leader_address=self.current_leader
        )

    def run_leader_election_loop(self):
        """
        Continuously check the leader's availability and trigger a leader election if needed.

        This background loop periodically pings the current leader. If the leader is unreachable,
        it initiates a leader election.
        """
        while True:
            time.sleep(5)  # Wait for 5 seconds between checks.
            if self.current_leader == self.my_address:
                # This node is the leader; optionally, it could ping peers here.
                continue
            else:
                try:
                    channel = grpc.insecure_channel(self.current_leader)
                    stub = message_service_pb2_grpc.ChatServiceStub(channel)
                    req = message_service_pb2.PingRequest(dummy="heartbeat")
                    stub.Ping(req, timeout=2)
                    channel.close()
                    continue
                except Exception as e:
                    print(f"Current leader {self.current_leader} unreachable: {e}")
                    self.elect_leader()

    def elect_leader(self):
        """
        Conduct a leader election by pinging all nodes and selecting the one with the smallest address.

        Returns:
            None: Updates the current leader and whether this node is the leader.
        """
        active_nodes = [self.my_address]
        # Ping all replica nodes to determine which nodes are active.
        for addr in self.replica_addresses:
            try:
                channel = grpc.insecure_channel(addr)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                req = message_service_pb2.PingRequest(dummy="election")
                stub.Ping(req, timeout=2)
                active_nodes.append(addr)
                channel.close()
            except Exception as e:
                print(f"Peer {addr} not reachable during election: {e}")
        # Choose the node with the smallest address as the leader.
        new_leader = min(active_nodes)
        with self.user_lock:
            self.current_leader = new_leader
            self.is_leader = (self.my_address == new_leader)
        print(f"Leader elected: {self.current_leader} (I am {'leader' if self.is_leader else 'not leader'})")

    # --- Account Management RPCs ---

    def CreateAccount(self, request, context):
        """
        RPC to create a new user account.

        Args:
            request (CreateAccountRequest): Contains username and hashed password.
            context: gRPC context.

        Returns:
            AuthResponse: Indicates whether account creation was successful.
        """
        username = request.username
        hashed_password = request.hashed_password
        print(f"Creating account for: {username}")
        with self.user_lock:
            if username in self.users:
                return message_service_pb2.AuthResponse(
                    success=False,
                    message="Account already exists"
                )
            # Create a new user and initialize an empty message queue.
            new_user = User(username, password=hashed_password)
            self.users[username] = new_user
            self.message_queues[username] = Queue()
            # Prepare update data for replication.
            update = {"username": username, "hashed_password": hashed_password}
            update_id = str(uuid.uuid4())
            self.replication_log.add(update_id)
            self.persist_state()
            self.replicate_update("CreateAccount", json.dumps(update), update_id)
            return message_service_pb2.AuthResponse(
                success=True,
                username=username,
                message="Account created successfully",
                unread_count=0
            )

    def Login(self, request, context):
        """
        RPC to log in a user.

        Args:
            request (LoginRequest): Contains username and hashed password.
            context: gRPC context.

        Returns:
            AuthResponse: Indicates success or failure of the login attempt.
        """
        username = request.username
        hashed_password = request.hashed_password
        print(f"Login attempt for: {username}")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.AuthResponse(
                    success=False,
                    message="Account does not exist"
                )
            user = self.users[username]
            if user.password != hashed_password:
                return message_service_pb2.AuthResponse(
                    success=False,
                    message="Incorrect password"
                )
            if username not in self.message_queues:
                self.message_queues[username] = Queue()
            # Get count of undelivered messages from the user's queue.
            unread_count = user.undelivered_messages.qsize()
            return message_service_pb2.AuthResponse(
                success=True,
                username=username,
                message="Login successful",
                unread_count=unread_count
            )

    def Logout(self, request, context):
        """
        RPC to log out a user.

        Args:
            request (LogoutRequest): Contains the username.
            context: gRPC context.

        Returns:
            StatusResponse: Indicates success or failure of logout.
        """
        username = request.username
        print(f"Logout request for: {username}")
        with self.user_lock:
            if username in self.active_users:
                del self.active_users[username]
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Logout successful"
                )
            else:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="User not logged in"
                )

    def DeleteAccount(self, request, context):
        """
        RPC to delete a user account.

        Args:
            request (UsernameRequest): Contains the username.
            context: gRPC context.

        Returns:
            StatusResponse: Indicates success or failure of the account deletion.
        """
        username = request.username
        print(f"Delete account request for: {username}")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Account does not exist"
                )
            user = self.users[username]
            # Prevent deletion if there are unread messages.
            if not user.undelivered_messages.empty():
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Cannot delete account with unread messages"
                )
            # Remove user data and associated message queue.
            del self.users[username]
            if username in self.active_users:
                del self.active_users[username]
            if username in self.message_queues:
                del self.message_queues[username]
            self.persist_state()
            return message_service_pb2.StatusResponse(
                success=True,
                message="Account deleted successfully"
            )

    # --- Messaging Operations ---

    def SendMessage(self, request, context):
        """
        RPC to send a message from one user to another.

        Args:
            request (SendMessageRequest): Contains sender, recipient, and message content.
            context: gRPC context.

        Returns:
            StatusResponse: Indicates whether the message was delivered immediately or queued.
        """
        sender = request.sender
        recipient = request.recipient
        content = request.content
        print(f"Message from {sender} to {recipient}")
        with self.user_lock:
            if sender not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Sender not found"
                )
            if recipient not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Recipient not found"
                )
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            full_message = f"From {sender} at {timestamp}: {content}"
            msg_data = {"sender": sender, "recipient": recipient, "content": content, "timestamp": timestamp}
            # Check if recipient is actively connected.
            if recipient in self.active_users:
                self.message_queues[recipient].put(
                    message_service_pb2.MessageResponse(
                        sender=sender,
                        content=content,
                        timestamp=timestamp
                    )
                )
                # Mark message as read for immediate delivery.
                self.users[recipient].add_read_message(full_message)
                resp_msg = "Message sent for immediate delivery"
            else:
                # Otherwise, queue the message for later delivery.
                self.users[recipient].queue_message(full_message)
                resp_msg = "Message queued for later delivery"
            update_id = str(uuid.uuid4())
            self.replication_log.add(update_id)
            self.persist_state()
            self.replicate_update("SendMessage", json.dumps(msg_data), update_id)
            return message_service_pb2.StatusResponse(
                success=True,
                message=resp_msg
            )

    def DeleteMessages(self, request, context):
        """
        RPC to delete messages for a user based on provided deletion criteria.

        Args:
            request (DeleteMessagesRequest): Contains the username and deletion criteria.
            context: gRPC context.

        Returns:
            StatusResponse: Indicates the number of messages deleted or failure.
        """
        username = request.username
        delete_info = request.delete_info
        print(f"Delete messages request from {username} with info: {delete_info}")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="User not found"
                )
            user = self.users[username]
            # Delete messages based on criteria and get count of deleted messages.
            deleted_count = user.delete_read_messages(delete_info)
            if deleted_count == 0:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="No messages deleted"
                )
            update = {"username": username, "delete_info": delete_info, "deleted_count": deleted_count}
            update_id = str(uuid.uuid4())
            self.replication_log.add(update_id)
            self.persist_state()
            self.replicate_update("DeleteMessages", json.dumps(update), update_id)
            return message_service_pb2.StatusResponse(
                success=True,
                message=f"Deleted {deleted_count} messages"
            )

    # --- Replication RPC ---

    def ReplicateOperation(self, request, context):
        """
        RPC invoked by other nodes to replicate an update operation.

        Args:
            request (ReplicationRequest): Contains operation details and a unique update ID.
            context: gRPC context.

        Returns:
            StatusResponse: Indicates whether the replication update was applied.
        """
        update_id = request.update_id
        with self.user_lock:
            # If the update has already been applied, ignore it.
            if update_id in self.replication_log:
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Update already applied"
                )
            self.replication_log.add(update_id)
            operation = request.operation
            data = json.loads(request.data)
            # Process the operation based on its type.
            if operation == "CreateAccount":
                username = data["username"]
                hashed_password = data["hashed_password"]
                if username not in self.users:
                    new_user = User(username, password=hashed_password)
                    self.users[username] = new_user
                    self.message_queues[username] = Queue()
            elif operation == "SendMessage":
                sender = data["sender"]
                recipient = data["recipient"]
                content = data["content"]
                timestamp = data["timestamp"]
                full_message = f"From {sender} at {timestamp}: {content}"
                if recipient in self.users:
                    if recipient in self.active_users:
                        self.message_queues[recipient].put(
                            message_service_pb2.MessageResponse(
                                sender=sender,
                                content=content,
                                timestamp=timestamp
                            )
                        )
                        self.users[recipient].add_read_message(full_message)
                    else:
                        self.users[recipient].queue_message(full_message)
            elif operation == "DeleteMessages":
                username = data["username"]
                delete_info = data["delete_info"]
                if username in self.users:
                    user = self.users[username]
                    user.delete_read_messages(delete_info)
            else:
                print(f"Unknown replication operation: {operation}")
            self.persist_state()
        return message_service_pb2.StatusResponse(
            success=True,
            message="Replication update applied"
        )

    # --- Other RPCs ---

    def SyncState(self, request, context):
        """
        RPC to return the current state as a JSON string for state synchronization.

        Args:
            request (SyncStateRequest): May contain a version field or be empty.
            context: gRPC context.

        Returns:
            SyncStateResponse: Contains the serialized state as JSON.
        """
        with self.user_lock:
            # Convert each message queue from a Queue to a list for serialization.
            mq = {username: list(q.queue) for username, q in self.message_queues.items()}
            # Note: If User objects are not directly serializable, they may need conversion.
            state = {
                "users": self.users,
                "message_queues": mq,
                "replication_log": list(self.replication_log)
            }
        state_json = json.dumps(state)
        return message_service_pb2.SyncStateResponse(state_json=state_json)

    def CheckUsername(self, request, context):
        """
        RPC to check if a username already exists.

        Args:
            request (UsernameRequest): Contains the username to check.
            context: gRPC context.

        Returns:
            UsernameResponse: Indicates whether the username exists.
        """
        print(f"Checking username: {request.username}")
        with self.user_lock:
            exists = request.username in self.users
        return message_service_pb2.UsernameResponse(
            exists=exists,
            message="Account exists" if exists else "Username available"
        )

    def ListAccounts(self, request, context):
        """
        RPC to list all accounts matching a given pattern.

        Args:
            request (ListAccountsRequest): Contains the username making the request and a search pattern.
            context: gRPC context.

        Returns:
            ListAccountsResponse: Contains a list of matching account usernames.
        """
        username = request.username
        pattern = request.pattern
        print(f"List accounts request from {username} with pattern: {pattern}")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.ListAccountsResponse(
                    success=False,
                    message="User not authenticated"
                )
            if not pattern:
                pattern = "*"
            # Filter the user list based on the provided pattern.
            matching_accounts = fnmatch.filter(self.users.keys(), pattern)
            return message_service_pb2.ListAccountsResponse(
                success=True,
                accounts=matching_accounts,
                message=f"Found {len(matching_accounts)} matching accounts"
            )

    def ViewMessages(self, request, context):
        """
        RPC to retrieve a specified number of undelivered messages for a user.

        Args:
            request (ViewMessagesRequest): Contains the username and number of messages to retrieve.
            context: gRPC context.

        Returns:
            ViewMessagesResponse: Contains the retrieved messages and a status message.
        """
        username = request.username
        count = request.count
        print(f"View messages request from {username} for {count} messages")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.ViewMessagesResponse(
                    success=False,
                    message="User not found"
                )
            user = self.users[username]
            if user.undelivered_messages.empty():
                return message_service_pb2.ViewMessagesResponse(
                    success=False,
                    message="No undelivered messages"
                )
            # Retrieve messages and update the state accordingly.
            messages_list = user.get_current_messages(count)
            self.persist_state()

            message_data_list = []
            # Parse each message to extract sender, content, and timestamp.
            for msg in messages_list:
                if msg.startswith("From "):
                    try:
                        remainder = msg[5:]
                        sender_and_timestamp, content = remainder.split(": ", 1)
                        sender, timestamp = sender_and_timestamp.split(" at ", 1)
                        message_data_list.append(message_service_pb2.MessageData(
                            sender=sender,
                            content=content,
                            timestamp=timestamp
                        ))
                    except Exception:
                        parts = msg.split(": ", 1)
                        if len(parts) == 2:
                            sender = parts[0].replace("From ", "")
                            content = parts[1]
                            message_data_list.append(message_service_pb2.MessageData(
                                sender=sender,
                                content=content,
                                timestamp=""
                            ))
                else:
                    message_data_list.append(message_service_pb2.MessageData(
                        sender="Unknown",
                        content=msg,
                        timestamp=""
                    ))
            return message_service_pb2.ViewMessagesResponse(
                success=True,
                messages=message_data_list,
                message=f"{len(message_data_list)} messages delivered"
            )

    def ReceiveMessages(self, request, context):
        """
        RPC that starts a streaming response to continuously deliver messages to a user.

        Args:
            request (UsernameRequest): Contains the username for which messages should be streamed.
            context: gRPC context.

        Yields:
            MessageResponse: A message to be delivered to the user.
        """
        username = request.username
        print(f"Starting message stream for {username}")
        with self.user_lock:
            if username not in self.users:
                # Abort stream if user is not found.
                context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
                return
            # Add the user's stream context to active users.
            self.active_users[username] = context
            if username not in self.message_queues:
                self.message_queues[username] = Queue()
        try:
            # Continuously yield messages as long as the stream is active.
            while context.is_active():
                try:
                    queue_obj = self.message_queues[username]
                    if not queue_obj.empty():
                        message = queue_obj.get(block=False)
                        yield message
                    else:
                        time.sleep(0.1)  # Avoid busy waiting if no message is available.
                except Exception as e:
                    print(f"Error in message stream for {username}: {e}")
                    break
        finally:
            with self.user_lock:
                # Remove the user from active users when the stream ends.
                if username in self.active_users:
                    del self.active_users[username]
                    print(f"Ended message stream for {username}")

def serve(port=50051, replica_addresses=None):
    """
    Set up and start the gRPC server.

    Args:
        port (int): Port to listen on.
        replica_addresses (list): List of replica addresses (host:port) for replication and leader election.
    """
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    message_service_pb2_grpc.add_ChatServiceServicer_to_server(
        ChatServiceServicer(port, replica_addresses), server
    )
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"Server started, listening on port {port}")
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("Server stopping...")
        server.stop(0)

if __name__ == '__main__':
    # Parse command-line arguments for port and replica addresses.
    parser = argparse.ArgumentParser(description='gRPC Chat Server with Persistence, Replication, and Leader Election')
    parser.add_argument('--port', type=int, default=50051, help='The server port')
    parser.add_argument('--replicas', type=str, default="",
                        help='Comma-separated list of replica addresses (host:port) for replication/election')
    args = parser.parse_args()
    # Process the replicas argument into a list if provided.
    replica_addrs = [addr.strip() for addr in args.replicas.split(",") if addr.strip()] if args.replicas else []
    serve(args.port, replica_addrs)