# grpc_server.py
import os
import sys
import time
import threading
import fnmatch
import grpc
import argparse
import json
import uuid
import socket
from concurrent import futures
from queue import Queue

# Add common directory to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import message_service_pb2
import message_service_pb2_grpc

from common.user import User
from common.hash_utils import hash_password
from common.persistence import load_state, save_state

class ChatServiceServicer(message_service_pb2_grpc.ChatServiceServicer):
    """
    Chat Service with persistence, replication, and leader election.
    """
    def __init__(self, port, replica_addresses=None):
        self.my_port = port  # store port to use in persistence
        # Load persisted state using the port (unique per server)
        state = load_state(self.my_port)
        self.users = state.get("users", {})  # {username: User}
        mq_data = state.get("message_queues", {})
        self.message_queues = {}
        for username, messages in mq_data.items():
            q = Queue()
            for msg in messages:
                q.put(msg)
            self.message_queues[username] = q
        self.replication_log = state.get("replication_log", set())
        
        self.user_lock = threading.Lock()
        self.active_users = {}  # {username: stream context}
        self.replica_addresses = replica_addresses if replica_addresses else []
        
        # Determine own address from hostname and provided port.
        self.my_address = f"{socket.gethostname()}:{port}"
        
        # Initially assume self is leader.
        self.current_leader = self.my_address
        self.is_leader = True
        
        # Start background thread for leader election.
        threading.Thread(target=self.run_leader_election_loop, daemon=True).start()
        
        print(f"Chat Service initialized on {self.my_address} with persistence, replication, and leader election.")
    
    def persist_state(self):
        """Persist state by converting non-pickleable objects to basic types."""
        mq = {username: list(q.queue) for username, q in self.message_queues.items()}
        state = {
            "users": self.users,
            "message_queues": mq,
            "replication_log": self.replication_log
        }
        save_state(state, self.my_port)
    
    def replicate_update(self, operation, data, update_id):
        req = message_service_pb2.ReplicationRequest(
            operation=operation,
            data=data,
            update_id=update_id
        )
        for addr in self.replica_addresses:
            try:
                channel = grpc.insecure_channel(addr)
                stub = message_service_pb2_grpc.ChatServiceStub(channel)
                response = stub.ReplicateOperation(req)
                print(f"Replicated update to {addr}: {response.message}")
                channel.close()
            except Exception as e:
                print(f"Replication to {addr} failed: {e}")
    
    # --- Leader Election and Heartbeat RPCs ---
    
    def Ping(self, request, context):
        return message_service_pb2.PingResponse(
            message=f"Pong from {self.my_address}",
            sender_id=self.my_address
        )
    
    def GetLeader(self, request, context):
        return message_service_pb2.LeaderResponse(
            leader_address=self.current_leader
        )
    
    def run_leader_election_loop(self):
        """Periodically ping the current leader; if unreachable, run election."""
        while True:
            time.sleep(5)
            if self.current_leader == self.my_address:
                # I'm the leader; optionally ping peers.
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
        """Ping all nodes and choose the one with the smallest address as leader."""
        active_nodes = [self.my_address]
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
        new_leader = min(active_nodes)
        with self.user_lock:
            self.current_leader = new_leader
            self.is_leader = (self.my_address == new_leader)
        print(f"Leader elected: {self.current_leader} (I am {'leader' if self.is_leader else 'not leader'})")
    
    # --- Account Management RPCs ---
    
    def CreateAccount(self, request, context):
        username = request.username
        hashed_password = request.hashed_password
        print(f"Creating account for: {username}")
        with self.user_lock:
            if username in self.users:
                return message_service_pb2.AuthResponse(
                    success=False,
                    message="Account already exists"
                )
            new_user = User(username, password=hashed_password)
            self.users[username] = new_user
            self.message_queues[username] = Queue()
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
            unread_count = user.undelivered_messages.qsize()
            return message_service_pb2.AuthResponse(
                success=True,
                username=username,
                message="Login successful",
                unread_count=unread_count
            )
    
    def Logout(self, request, context):
        """Logout RPC implementation."""
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
        username = request.username
        print(f"Delete account request for: {username}")
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Account does not exist"
                )
            user = self.users[username]
            if not user.undelivered_messages.empty():
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Cannot delete account with unread messages"
                )
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
            if recipient in self.active_users:
                self.message_queues[recipient].put(
                    message_service_pb2.MessageResponse(
                        sender=sender,
                        content=content,
                        timestamp=timestamp
                    )
                )
                self.users[recipient].add_read_message(full_message)
                resp_msg = "Message sent for immediate delivery"
            else:
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
        update_id = request.update_id
        with self.user_lock:
            if update_id in self.replication_log:
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Update already applied"
                )
            self.replication_log.add(update_id)
            operation = request.operation
            data = json.loads(request.data)
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
    
    def CheckUsername(self, request, context):
        print(f"Checking username: {request.username}")
        with self.user_lock:
            exists = request.username in self.users
        return message_service_pb2.UsernameResponse(
            exists=exists,
            message="Account exists" if exists else "Username available"
        )
    
    def ListAccounts(self, request, context):
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
            matching_accounts = fnmatch.filter(self.users.keys(), pattern)
            return message_service_pb2.ListAccountsResponse(
                success=True,
                accounts=matching_accounts,
                message=f"Found {len(matching_accounts)} matching accounts"
            )
    
    def ViewMessages(self, request, context):
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
            messages_list = user.get_current_messages(count)
            message_data_list = []
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
        username = request.username
        print(f"Starting message stream for {username}")
        with self.user_lock:
            if username not in self.users:
                context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
                return
            self.active_users[username] = context
            if username not in self.message_queues:
                self.message_queues[username] = Queue()
        try:
            while context.is_active():
                try:
                    queue_obj = self.message_queues[username]
                    if not queue_obj.empty():
                        message = queue_obj.get(block=False)
                        yield message
                    else:
                        time.sleep(0.1)
                except Exception as e:
                    print(f"Error in message stream for {username}: {e}")
                    break
        finally:
            with self.user_lock:
                if username in self.active_users:
                    del self.active_users[username]
                    print(f"Ended message stream for {username}")

def serve(port=50051, replica_addresses=None):
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
    parser = argparse.ArgumentParser(description='gRPC Chat Server with Persistence, Replication, and Leader Election')
    parser.add_argument('--port', type=int, default=50051, help='The server port')
    parser.add_argument('--replicas', type=str, default="",
                        help='Comma-separated list of replica addresses (host:port) for replication/election')
    args = parser.parse_args()
    replica_addrs = [addr.strip() for addr in args.replicas.split(",") if addr.strip()] if args.replicas else []
    serve(args.port, replica_addrs)