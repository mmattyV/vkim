# service/replicated_chat_service.py

import os
import sys
import time
import threading
import json
import logging
import grpc
from concurrent import futures

# Adjust the path if needed
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.user import User
import message_service_pb2
import message_service_pb2_grpc

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReplicatedChatServiceServicer(message_service_pb2_grpc.ChatServiceServicer):
    """
    Simplified Chat Service that uses a Primary–Backup manager instead of Raft.
    """
    def __init__(self, db, pb_manager):
        """
        :param db: Instance of ChatDatabase for persistent storage.
        :param pb_manager: Instance of PrimaryBackupManager for replication.
        """
        self.db = db
        self.pb_manager = pb_manager
        
        # Locks for thread safety
        self.user_lock = threading.Lock()
        
        # Ephemeral session management
        self.active_users = {}   # {username: stream_context}
        self.message_queues = {} # {username: [MessageResponse, ...]}
        
        # In-memory user cache
        self.user_cache = {}
        self.cache_lock = threading.Lock()
        
        logger.info("Replicated Chat Service initialized (Primary–Backup).")
    
    # ----------------------------------------------------------------------
    # Helper methods
    # ----------------------------------------------------------------------
    
    def get_user(self, username):
        """
        Retrieve or create a User object in an in-memory cache.
        Loads unread messages from the database if necessary.
        """
        with self.cache_lock:
            if username not in self.user_cache:
                # Check if user exists in DB
                if self.db.user_exists(username):
                    user = User(username)
                    
                    # Load unread messages
                    unread_messages = self.db.get_unread_messages(username, 1000)
                    for msg in unread_messages:
                        formatted_msg = f"From {msg['sender']} at {msg['timestamp']}: {msg['content']}"
                        user.queue_message(formatted_msg)
                    
                    self.user_cache[username] = user
                else:
                    return None
            return self.user_cache[username]
    
    def invalidate_cache(self, username=None):
        """
        Invalidate the user cache for a specific user or all users.
        """
        with self.cache_lock:
            if username:
                self.user_cache.pop(username, None)
            else:
                self.user_cache.clear()
    
    def _is_primary(self):
        """
        Check if this replica is currently the primary.
        """
        return (self.pb_manager.role == "primary")
    
    def _reject_non_primary(self, context):
        """
        Helper to return an error response if this replica is not the primary.
        You could also set trailing metadata with the known primary host/port.
        """
        # Optional: set metadata to inform the client about the primary
        # context.set_trailing_metadata((
        #     ('primary_host', self.pb_manager.primary_host or ""),
        #     ('primary_port', str(self.pb_manager.primary_port or 0)),
        #     ('redirect', 'true')
        # ))
        
        return message_service_pb2.StatusResponse(
            success=False,
            message="This replica is not the primary. Please contact the primary for write operations."
        )
    
    # ----------------------------------------------------------------------
    # gRPC Method Implementations
    # ----------------------------------------------------------------------
    
    def CheckUsername(self, request, context):
        """
        Check if a username already exists (READ).
        This can be served by any replica.
        """
        logger.info(f"Checking username: {request.username}")
        
        exists = self.db.user_exists(request.username)
        return message_service_pb2.UsernameResponse(
            exists=exists,
            message="Account exists" if exists else "Username available"
        )
    
    def CreateAccount(self, request, context):
        """
        Create a new user account (WRITE).
        Only allowed on primary. Then replicate to backups.
        """
        username = request.username
        hashed_password = request.hashed_password
        logger.info(f"CreateAccount request for: {username}")
        
        # 1. Ensure we are primary
        if not self._is_primary():
            # Return an AuthResponse to match the method signature
            return message_service_pb2.AuthResponse(
                success=False,
                message="Not primary. Please use the primary for writes."
            )
        
        # 2. Check if user exists
        if self.db.user_exists(username):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Account already exists"
            )
        
        # 3. Create locally
        self.db.create_user(username, hashed_password)
        self.invalidate_cache(username)
        self.message_queues[username] = []
        
        # 4. Replicate to backups
        self.pb_manager.push_update_to_backups(
            update_type="create_user",
            parameters={
                "username": username,
                "hashed_password": hashed_password
            }
        )
        
        return message_service_pb2.AuthResponse(
            success=True,
            username=username,
            message="Account created successfully",
            unread_count=0
        )
    
    def Login(self, request, context):
        """
        Log in a user (READ + ephemeral session).
        Allowed on any replica if we want to support read on backups.
        """
        username = request.username
        hashed_password = request.hashed_password
        logger.info(f"Login attempt for: {username}")
        
        if not self.db.user_exists(username):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Account does not exist"
            )
        
        if not self.db.verify_user(username, hashed_password):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Incorrect password"
            )
        
        # Setup ephemeral user object if not cached
        user = self.get_user(username)
        if username not in self.message_queues:
            self.message_queues[username] = []
        
        unread_count = self.db.get_unread_message_count(username)
        
        return message_service_pb2.AuthResponse(
            success=True,
            username=username,
            message="Login successful",
            unread_count=unread_count
        )
    
    def Logout(self, request, context):
        """
        Log out a user (ephemeral only).
        """
        username = request.username
        logger.info(f"Logout request for: {username}")
        
        with self.user_lock:
            if username in self.active_users:
                del self.active_users[username]
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Logout successful"
                )
        
        return message_service_pb2.StatusResponse(
            success=False,
            message="User not logged in"
        )
    
    def DeleteAccount(self, request, context):
        """
        Delete a user account (WRITE).
        Only on primary; replicate to backups.
        """
        username = request.username
        logger.info(f"DeleteAccount request for: {username}")
        
        if not self._is_primary():
            return message_service_pb2.StatusResponse(
                success=False,
                message="Not primary. Please use the primary for writes."
            )
        
        if not self.db.user_exists(username):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Account does not exist"
            )
        
        # Perform local delete
        success, msg = self.db.delete_user(username)
        if not success:
            return message_service_pb2.StatusResponse(success=False, message=msg)
        
        # Cleanup ephemeral
        with self.user_lock:
            self.active_users.pop(username, None)
            self.message_queues.pop(username, None)
        self.invalidate_cache(username)
        
        # Replicate to backups
        self.pb_manager.push_update_to_backups(
            update_type="delete_user",
            parameters={"username": username}
        )
        
        return message_service_pb2.StatusResponse(
            success=True,
            message="Account deleted successfully"
        )
    
    def ListAccounts(self, request, context):
        """
        List user accounts matching a pattern (READ).
        Can be served by any replica.
        """
        username = request.username
        pattern = request.pattern
        logger.info(f"ListAccounts from {username} with pattern: {pattern}")
        
        if not self.db.user_exists(username):
            return message_service_pb2.ListAccountsResponse(
                success=False,
                message="User not authenticated"
            )
        
        if not pattern:
            pattern = "*"
        
        matching_accounts = self.db.list_users(pattern)
        return message_service_pb2.ListAccountsResponse(
            success=True,
            accounts=matching_accounts,
            message=f"Found {len(matching_accounts)} matching accounts"
        )
    
    def SendMessage(self, request, context):
        """
        Send a message from one user to another (WRITE).
        Only on primary; replicate to backups.
        """
        sender = request.sender
        recipient = request.recipient
        content = request.content
        logger.info(f"SendMessage from {sender} to {recipient}")
        
        if not self._is_primary():
            return message_service_pb2.StatusResponse(
                success=False,
                message="Not primary. Please use the primary for writes."
            )
        
        # Verify existence
        if not self.db.user_exists(sender):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Sender not found"
            )
        if not self.db.user_exists(recipient):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Recipient not found"
            )
        
        # Queue message locally
        timestamp = self.db.queue_message(sender, recipient, content)
        
        # Push to backups
        self.pb_manager.push_update_to_backups(
            update_type="queue_message",
            parameters={
                "sender": sender,
                "recipient": recipient,
                "content": content
            }
        )
        
        # Immediate ephemeral delivery if recipient is active
        message_data = message_service_pb2.MessageResponse(
            sender=sender,
            content=content,
            timestamp=timestamp
        )
        with self.user_lock:
            if recipient in self.active_users:
                self.message_queues[recipient].append(message_data)
        
        return message_service_pb2.StatusResponse(
            success=True,
            message="Message sent"
        )
    
    def ViewMessages(self, request, context):
        """
        Retrieve undelivered (unread) messages for a user (READ + marks read).
        Marking messages as read is effectively a WRITE operation.
        For strong consistency, only allow on primary -> replicate to backups.
        """
        username = request.username
        count = request.count
        logger.info(f"ViewMessages request from {username} for {count} messages")
        
        # If you want to allow reading from backups (with eventual consistency), remove the check below.
        # But if you want consistent "mark as read," keep it on primary only:
        if not self._is_primary():
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="Not primary. Please use the primary to mark messages as read."
            )
        
        if not self.db.user_exists(username):
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="User not found"
            )
        
        # Mark them as read in local DB
        unread_messages = self.db.get_unread_messages(username, count)
        if not unread_messages:
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="No undelivered messages"
            )
        
        # Convert to proto objects
        message_data_list = []
        for msg in unread_messages:
            message_data_list.append(message_service_pb2.MessageData(
                sender=msg['sender'],
                content=msg['content'],
                timestamp=msg['timestamp']
            ))
        
        # Invalidate cache so next time user reloads
        self.invalidate_cache(username)
        
        # Replicate the "mark as read" operation
        self.pb_manager.push_update_to_backups(
            update_type="view_messages",
            parameters={
                "username": username,
                "count": str(count)
            }
        )
        
        return message_service_pb2.ViewMessagesResponse(
            success=True,
            messages=message_data_list,
            message=f"{len(message_data_list)} messages delivered"
        )
    
    def DeleteMessages(self, request, context):
        """
        Delete read messages from a user's mailbox (WRITE).
        Only on primary; replicate to backups.
        """
        username = request.username
        delete_info = request.delete_info
        logger.info(f"DeleteMessages request from {username} with info: {delete_info}")
        
        if not self._is_primary():
            return message_service_pb2.StatusResponse(
                success=False,
                message="Not primary. Please use the primary for writes."
            )
        
        if not self.db.user_exists(username):
            return message_service_pb2.StatusResponse(
                success=False,
                message="User not found"
            )
        
        deleted_count = self.db.delete_read_messages(username, delete_info)
        self.invalidate_cache(username)
        
        # Replicate
        self.pb_manager.push_update_to_backups(
            update_type="delete_messages",
            parameters={
                "username": username,
                "delete_info": delete_info
            }
        )
        
        if deleted_count == 0:
            return message_service_pb2.StatusResponse(
                success=False,
                message="No messages deleted"
            )
        
        return message_service_pb2.StatusResponse(
            success=True,
            message=f"Deleted {deleted_count} messages"
        )
    
    def ReceiveMessages(self, request, context):
        """
        Stream real-time messages to the client (READ).
        Can be served by any replica if data is replicated.
        """
        username = request.username
        logger.info(f"Starting message stream for {username}")
        
        if not self.db.user_exists(username):
            context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
            return
        
        # Mark user as active
        with self.user_lock:
            self.active_users[username] = context
            if username not in self.message_queues:
                self.message_queues[username] = []
        
        try:
            # First deliver any unread messages from DB
            unread_messages = self.db.get_unread_messages(username, 100)
            for msg in unread_messages:
                yield message_service_pb2.MessageResponse(
                    sender=msg['sender'],
                    content=msg['content'],
                    timestamp=msg['timestamp']
                )
            
            # Then keep streaming ephemeral queue
            while context.is_active():
                with self.user_lock:
                    if self.message_queues[username]:
                        queue_copy = list(self.message_queues[username])
                        self.message_queues[username].clear()
                    
                for message in queue_copy:
                    yield message
                
                time.sleep(0.1)
        
        finally:
            # Clean up on disconnect
            with self.user_lock:
                if username in self.active_users:
                    del self.active_users[username]
                    logger.info(f"Ended message stream for {username}")
