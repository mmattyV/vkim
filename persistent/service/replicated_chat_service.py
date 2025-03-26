# service/replicated_chat_service.py
import os
import sys
import time
import threading
import json
import logging
import grpc
from concurrent import futures

# Add common directory to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import original chat service classes
from common.user import User
import message_service_pb2
import message_service_pb2_grpc

# Import replication manager
from replication.replica_manager import ReplicaManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReplicatedChatServiceServicer(message_service_pb2_grpc.ChatServiceServicer):
    """
    Implementation of the gRPC ChatService with replication support.
    This extends the original chat service to provide persistence and fault tolerance.
    """
    def __init__(self, replica_manager):
        # Store the replica manager
        self.replica_manager = replica_manager
        
        # Locks for thread safety
        self.user_lock = threading.Lock()
        
        # User session management (in-memory only, not persistent)
        self.active_users = {}  # Dictionary to store active client streams {username: stream_context}
        self.message_queues = {}  # {username: Queue of messages}
        
        # Cache for User objects (prevent frequent database access)
        self.user_cache = {}
        self.cache_lock = threading.Lock()
        
        logger.info("Replicated Chat Service initialized")
        
    def get_user(self, username):
        """Get a User object for the given username, creating it if necessary."""
        with self.cache_lock:
            if username not in self.user_cache:
                # Check if user exists in database
                db = self.replica_manager.db
                if db.user_exists(username):
                    # Create User object from database data
                    user = User(username)
                    
                    # Load unread messages from database
                    unread_messages = db.get_unread_messages(username, 1000)
                    for msg in unread_messages:
                        formatted_msg = f"From {msg['sender']} at {msg['timestamp']}: {msg['content']}"
                        user.queue_message(formatted_msg)
                        
                    self.user_cache[username] = user
                else:
                    return None
                    
            return self.user_cache[username]
            
    # service/replicated_chat_service.py (continued)
    def invalidate_cache(self, username=None):
        """Invalidate the user cache for a specific user or all users."""
        with self.cache_lock:
            if username:
                if username in self.user_cache:
                    del self.user_cache[username]
            else:
                self.user_cache.clear()
                
    def CheckUsername(self, request, context):
        """Check if a username already exists"""
        print(f"Checking username: {request.username}")
        
        db = self.replica_manager.db
        exists = db.user_exists(request.username)
        
        return message_service_pb2.UsernameResponse(
            exists=exists,
            message="Account exists" if exists else "Username available"
        )
        
    def CreateAccount(self, request, context):
        """Create a new user account"""
        username = request.username
        hashed_password = request.hashed_password
        
        logger.info(f"Creating account for: {username}")
        
        db = self.replica_manager.db
        
        # Check if username exists
        if db.user_exists(username):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Account already exists"
            )
            
        # Forward operation to leader if we're not the leader
        result = self.replica_manager.handle_client_operation(
            "create_user", 
            username=username, 
            hashed_password=hashed_password
        )
        
        # Log the result for debugging
        logger.info(f"Operation result: {result}")
        
        # Check for redirection
        if isinstance(result, dict) and result.get("redirect"):
            # Set gRPC metadata for client redirection
            logger.info(f"Redirecting to leader: {result['leader_id']}")
            context.set_trailing_metadata((
                ('leader_host', result['leader_host']),
                ('leader_port', str(result['leader_port'])),
                ('leader_id', result['leader_id']),
                ('redirect', 'true')
            ))
            return message_service_pb2.AuthResponse(
                success=False,
                message="Operation redirected to leader"
            )
            
        # Check for error
        if isinstance(result, dict) and result.get("error"):
            logger.warning(f"Operation error: {result.get('message')}")
            return message_service_pb2.AuthResponse(
                success=False,
                message=result.get("message", "Unknown error")
            )
        
        # If we got a log_id (operation was successful)
        if isinstance(result, int):
            logger.info(f"Account created with log_id: {result}")
            # Create user in local database (if leader) and invalidate cache
            self.invalidate_cache(username)
            
            # Initialize message queue for streaming
            self.message_queues[username] = []
            
            return message_service_pb2.AuthResponse(
                success=True,
                username=username,
                message="Account created successfully",
                unread_count=0
            )
        
        # Unknown result type
        logger.error(f"Unknown result type: {type(result)}")
        return message_service_pb2.AuthResponse(
            success=False,
            message="Internal server error"
        )
        
    def Login(self, request, context):
        """Authenticate a user"""
        username = request.username
        hashed_password = request.hashed_password
        
        logger.info(f"Login attempt for: {username}")
        
        db = self.replica_manager.db
        
        # Check if user exists and password matches
        if not db.user_exists(username):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Account does not exist"
            )
            
        if not db.verify_user(username, hashed_password):
            return message_service_pb2.AuthResponse(
                success=False,
                message="Incorrect password"
            )
            
        # Get or create user object
        user = self.get_user(username)
        
        # Track active user
        if username not in self.message_queues:
            self.message_queues[username] = []
            
        unread_count = db.get_unread_message_count(username)
        
        return message_service_pb2.AuthResponse(
            success=True,
            username=username,
            message="Login successful",
            unread_count=unread_count
        )
        
    def Logout(self, request, context):
        """Log out a user"""
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
        """Delete a user account"""
        username = request.username
        
        logger.info(f"Delete account request for: {username}")
        
        db = self.replica_manager.db
        
        # Check if user exists
        if not db.user_exists(username):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Account does not exist"
            )
            
        # Forward operation to leader if we're not the leader
        result = self.replica_manager.handle_client_operation(
            "delete_user",
            username=username
        )
        
        # Check for redirection
        if isinstance(result, dict) and result.get("redirect"):
            # Set gRPC metadata for client redirection
            context.set_trailing_metadata((
                ('leader_host', result['leader_host']),
                ('leader_port', str(result['leader_port'])),
                ('leader_id', result['leader_id']),
                ('redirect', 'true')
            ))
            return message_service_pb2.StatusResponse(
                success=False,
                message="Operation redirected to leader"
            )
            
        # Check for error
        if isinstance(result, dict) and result.get("error"):
            return message_service_pb2.StatusResponse(
                success=False,
                message=result.get("message", "Unknown error")
            )
            
        # Delete user from local memory
        with self.user_lock:
            if username in self.active_users:
                del self.active_users[username]
                
            if username in self.message_queues:
                del self.message_queues[username]
                
        self.invalidate_cache(username)
        
        return message_service_pb2.StatusResponse(
            success=True,
            message="Account deleted successfully"
        )
        
    def ListAccounts(self, request, context):
        """List user accounts matching a pattern"""
        username = request.username
        pattern = request.pattern
        
        logger.info(f"List accounts request from {username} with pattern: {pattern}")
        
        db = self.replica_manager.db
        
        # Check if user exists
        if not db.user_exists(username):
            return message_service_pb2.ListAccountsResponse(
                success=False,
                message="User not authenticated"
            )
            
        if not pattern:
            pattern = "*"
            
        # Find accounts matching the pattern
        matching_accounts = db.list_users(pattern)
        
        return message_service_pb2.ListAccountsResponse(
            success=True,
            accounts=matching_accounts,
            message=f"Found {len(matching_accounts)} matching accounts"
        )
        
    def SendMessage(self, request, context):
        """Send a message from one user to another"""
        sender = request.sender
        recipient = request.recipient
        content = request.content
        
        logger.info(f"Message from {sender} to {recipient}")
        
        db = self.replica_manager.db
        
        # Verify sender and recipient exist
        if not db.user_exists(sender):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Sender not found"
            )
            
        if not db.user_exists(recipient):
            return message_service_pb2.StatusResponse(
                success=False,
                message="Recipient not found"
            )
            
        # Forward operation to leader if we're not the leader
        result = self.replica_manager.handle_client_operation(
            "queue_message",
            sender=sender,
            recipient=recipient,
            content=content
        )
        
        # Check for redirection
        if isinstance(result, dict) and result.get("redirect"):
            # Set gRPC metadata for client redirection
            context.set_trailing_metadata((
                ('leader_host', result['leader_host']),
                ('leader_port', str(result['leader_port'])),
                ('leader_id', result['leader_id']),
                ('redirect', 'true')
            ))
            return message_service_pb2.StatusResponse(
                success=False,
                message="Operation redirected to leader"
            )
            
        # Check for error
        if isinstance(result, dict) and result.get("error"):
            return message_service_pb2.StatusResponse(
                success=False,
                message=result.get("message", "Unknown error")
            )
            
        # Store message in database and get timestamp
        timestamp = db.queue_message(sender, recipient, content)
        
        # Create message data for streaming
        message_data = message_service_pb2.MessageResponse(
            sender=sender,
            content=content,
            timestamp=timestamp
        )
        
        # If the recipient is actively streaming, deliver immediately
        if recipient in self.active_users:
            self.message_queues[recipient].append(message_data)
            
            # Also update the user cache if present
            with self.cache_lock:
                if recipient in self.user_cache:
                    full_message = f"From {sender} at {timestamp}: {content}"
                    self.user_cache[recipient].add_read_message(full_message)
                    
            return message_service_pb2.StatusResponse(
                success=True,
                message="Message sent for immediate delivery"
            )
        else:
            # Otherwise it's already queued in the database
            return message_service_pb2.StatusResponse(
                success=True,
                message="Message queued for later delivery"
            )
            
    def ViewMessages(self, request, context):
        """Retrieve undelivered messages for a user"""
        username = request.username
        count = request.count
        
        logger.info(f"View messages request from {username} for {count} messages")
        
        db = self.replica_manager.db
        
        # Check if user exists
        if not db.user_exists(username):
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="User not found"
            )
            
        # Forward operation to leader if we're not the leader
        result = self.replica_manager.handle_client_operation(
            "mark_messages_read",
            username=username,
            count=count
        )
        
        # Check for redirection
        if isinstance(result, dict) and result.get("redirect"):
            # Set gRPC metadata for client redirection
            context.set_trailing_metadata((
                ('leader_host', result['leader_host']),
                ('leader_port', str(result['leader_port'])),
                ('leader_id', result['leader_id']),
                ('redirect', 'true')
            ))
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="Operation redirected to leader"
            )
            
        # Get unread messages from database
        unread_messages = db.get_unread_messages(username, count)
        
        if not unread_messages:
            return message_service_pb2.ViewMessagesResponse(
                success=False,
                message="No undelivered messages"
            )
            
        # Convert to message data objects
        message_data_list = []
        for msg in unread_messages:
            message_data_list.append(message_service_pb2.MessageData(
                sender=msg['sender'],
                content=msg['content'],
                timestamp=msg['timestamp']
            ))
            
        # Update user cache
        self.invalidate_cache(username)
            
        return message_service_pb2.ViewMessagesResponse(
            success=True,
            messages=message_data_list,
            message=f"{len(message_data_list)} messages delivered"
        )
        
    def DeleteMessages(self, request, context):
        """Delete messages from a user's read messages"""
        username = request.username
        delete_info = request.delete_info
        
        logger.info(f"Delete messages request from {username} with info: {delete_info}")
        
        db = self.replica_manager.db
        
        # Check if user exists
        if not db.user_exists(username):
            return message_service_pb2.StatusResponse(
                success=False,
                message="User not found"
            )
            
        # Forward operation to leader if we're not the leader
        result = self.replica_manager.handle_client_operation(
            "delete_messages",
            username=username,
            delete_info=delete_info
        )
        
        # Check for redirection
        if isinstance(result, dict) and result.get("redirect"):
            # Set gRPC metadata for client redirection
            context.set_trailing_metadata((
                ('leader_host', result['leader_host']),
                ('leader_port', str(result['leader_port'])),
                ('leader_id', result['leader_id']),
                ('redirect', 'true')
            ))
            return message_service_pb2.StatusResponse(
                success=False,
                message="Operation redirected to leader"
            )
            
        # Delete messages
        deleted_count = db.delete_read_messages(username, delete_info)
        
        # Update user cache
        self.invalidate_cache(username)
        
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
        """Stream real-time messages to the client"""
        username = request.username
        
        logger.info(f"Starting message stream for {username}")
        
        db = self.replica_manager.db
        
        # Verify user exists
        if not db.user_exists(username):
            context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
            return
            
        # Mark user as active and store the context for cancellation
        with self.user_lock:
            self.active_users[username] = context
            
            # Ensure message queue exists
            if username not in self.message_queues:
                self.message_queues[username] = []
        
        try:
            # First deliver any unread messages from database
            unread_messages = db.get_unread_messages(username, 100)
            for msg in unread_messages:
                yield message_service_pb2.MessageResponse(
                    sender=msg['sender'],
                    content=msg['content'],
                    timestamp=msg['timestamp']
                )
                
            # Keep streaming until client disconnects
            while context.is_active():
                # Check for new messages in the queue
                if username in self.message_queues and self.message_queues[username]:
                    with self.user_lock:
                        message_queue = self.message_queues[username]
                        if message_queue:
                            for message in message_queue:
                                yield message
                            # Clear the queue after sending
                            self.message_queues[username] = []
                            
                # Sleep to prevent CPU spinning
                time.sleep(0.1)
                    
        finally:
            # Clean up when stream ends
            with self.user_lock:
                if username in self.active_users:
                    del self.active_users[username]
                    logger.info(f"Ended message stream for {username}")