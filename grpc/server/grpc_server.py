
import os
import sys
import time
import threading
import fnmatch
import grpc
import argparse
from concurrent import futures
from queue import Queue

# Add common directory to path for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import generated protobuf modules
import message_service_pb2
import message_service_pb2_grpc

# Import user class from the original implementation
from common.user import User
from common.hash_utils import hash_password

class ChatServiceServicer(message_service_pb2_grpc.ChatServiceServicer):
    """
    Implementation of the gRPC ChatService defined in chat.proto
    
    This server handles user authentication, message routing, and
    manages user accounts and their messages.
    """
    def __init__(self):
        # Locks for thread safety
        self.user_lock = threading.Lock()
        
        # User data structures
        self.users = {}  # Dictionary to store User objects {username: User}
        self.active_users = {}  # Dictionary to store active client streams {username: stream_context}
        
        # Message delivery queues for streaming
        self.message_queues = {}  # {username: Queue of messages}
        
        print("Chat Service initialized")
        
    def CheckUsername(self, request, context):
        """Check if a username already exists"""
        print(f"Checking username: {request.username}")
        
        with self.user_lock:
            exists = request.username in self.users
        
        return message_service_pb2.UsernameResponse(
            exists=exists,
            message="Account exists" if exists else "Username available"
        )
        
    def CreateAccount(self, request, context):
        """Create a new user account"""
        username = request.username
        hashed_password = request.hashed_password
        
        print(f"Creating account for: {username}")
        
        with self.user_lock:
            if username in self.users:
                return message_service_pb2.AuthResponse(
                    success=False,
                    message="Account already exists"
                )
            
            # Create a new user
            new_user = User(username, password=hashed_password)
            self.users[username] = new_user
            
            # Initialize message queue for streaming
            self.message_queues[username] = Queue()
            
            return message_service_pb2.AuthResponse(
                success=True,
                username=username,
                message="Account created successfully",
                unread_count=0
            )
            
    def Login(self, request, context):
        """Authenticate a user"""
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
                
            # Track active user
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
        """Log out a user"""
        username = request.username
        
        print(f"Logout request for: {username}")
        
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
        
        print(f"Delete account request for: {username}")
        
        with self.user_lock:
            if username not in self.users:
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Account does not exist"
                )
                
            user = self.users[username]
            
            # Check for unread messages
            if not user.undelivered_messages.empty():
                return message_service_pb2.StatusResponse(
                    success=False,
                    message="Cannot delete account with unread messages"
                )
                
            # Remove user from data structures
            del self.users[username]
            
            if username in self.active_users:
                del self.active_users[username]
                
            if username in self.message_queues:
                del self.message_queues[username]
                
            return message_service_pb2.StatusResponse(
                success=True,
                message="Account deleted successfully"
            )
            
    def ListAccounts(self, request, context):
        """List user accounts matching a pattern"""
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
                
            # Find accounts matching the pattern
            matching_accounts = fnmatch.filter(self.users.keys(), pattern)
            
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
                
            full_message = f"From {sender}: {content}"
            
            # Create message data
            message_data = message_service_pb2.MessageResponse(
                sender=sender,
                content=content,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # Queue message for streaming to recipient if they have an active stream
            if recipient in self.message_queues:
                self.message_queues[recipient].put(message_data)
                
            # If recipient is not active, store message for later delivery
            if recipient not in self.active_users:
                self.users[recipient].queue_message(full_message)
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Message queued for later delivery"
                )
            else:
                # Message will be delivered via the stream
                self.users[recipient].add_read_message(full_message)
                return message_service_pb2.StatusResponse(
                    success=True,
                    message="Message sent for immediate delivery"
                )
                
    def ViewMessages(self, request, context):
        """Retrieve undelivered messages for a user"""
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
                
            # Get messages from the queue
            messages_list = user.get_current_messages(count)
            
            # Convert to message data objects
            message_data_list = []
            for msg in messages_list:
                # Parse message format "From sender: content"
                if msg.startswith("From "):
                    parts = msg.split(": ", 1)
                    if len(parts) == 2:
                        sender = parts[0].replace("From ", "")
                        content = parts[1]
                        message_data_list.append(message_service_pb2.MessageData(
                            sender=sender,
                            content=content,
                            timestamp=""  # Original messages don't have timestamps
                        ))
                    else:
                        # Fallback for improperly formatted messages
                        message_data_list.append(message_service_pb2.MessageData(
                            sender="Unknown",
                            content=msg,
                            timestamp=""
                        ))
                else:
                    # Fallback for improperly formatted messages
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
            
    def DeleteMessages(self, request, context):
        """Delete messages from a user's read messages"""
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
            
            # Delete messages
            deleted_count = user.delete_read_messages(delete_info)
            
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
        
        print(f"Starting message stream for {username}")
        
        # Verify user exists
        with self.user_lock:
            if username not in self.users:
                context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
                return
                
            # Mark user as active and store the context for cancellation
            self.active_users[username] = context
            
            # Ensure message queue exists
            if username not in self.message_queues:
                self.message_queues[username] = Queue()
        
        try:
            # Keep streaming until client disconnects
            while context.is_active():
                # Check for new messages in the queue
                try:
                    message_queue = self.message_queues[username]
                    
                    # Non-blocking check for messages
                    if not message_queue.empty():
                        message = message_queue.get(block=False)
                        yield message
                    else:
                        # Sleep to prevent CPU spinning
                        time.sleep(0.1)
                        
                except Exception as e:
                    print(f"Error in message stream for {username}: {e}")
                    break
                    
        finally:
            # Clean up when stream ends
            with self.user_lock:
                if username in self.active_users:
                    del self.active_users[username]
                    print(f"Ended message stream for {username}")

def serve(port=50051):
    """Start the gRPC server"""
    # Create a gRPC server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    
    # Add the servicer to the server
    message_service_pb2_grpc.add_ChatServiceServicer_to_server(
        ChatServiceServicer(), server
    )
    
    # Add secure/insecure port
    server.add_insecure_port(f'[::]:{port}')
    
    # Start the server
    server.start()
    print(f"Server started, listening on port {port}")
    
    # Keep the server running
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        print("Server stopping...")
        server.stop(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='gRPC Chat Server')
    parser.add_argument('--port', type=int, default=50051, help='The server port')
    args = parser.parse_args()
    
    serve(args.port)