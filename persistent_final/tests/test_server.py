import unittest
import threading
import time
import fnmatch
import sys
import os
from queue import Queue
from unittest.mock import MagicMock, Mock

# Add the project root to sys.path so that the server package can be found.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import the ChatServiceServicer and serve function directly.
from server.grpc_server import ChatServiceServicer, serve

from common.user import User
import message_service_pb2

# --- Dummy Context for simulating gRPC calls ---
class DummyContext:
    def __init__(self):
        self.aborted = False
        self.abort_code = None
        self.abort_details = None

    def is_active(self):
        return True

    def abort(self, code, details):
        self.aborted = True
        self.abort_code = code
        self.abort_details = details
        raise Exception(f"Aborted: {code}, {details}")

# --- Tests for ChatServiceServicer ---
class TestChatServiceServicer(unittest.TestCase):

    def setUp(self):
        # Create an instance of ChatServiceServicer and use empty state dictionaries for testing.
        self.servicer = ChatServiceServicer(port=50051)
        self.servicer.users = {}
        self.servicer.active_users = {}
        self.servicer.message_queues = {}
        self.ctx = DummyContext()

    # --- Account Management Tests ---
    def test_check_username_nonexistent(self):
        req = message_service_pb2.UsernameRequest(username="newuser")
        resp = self.servicer.CheckUsername(req, self.ctx)
        self.assertFalse(resp.exists)
        self.assertEqual(resp.message, "Username available")

    def test_check_username_exists(self):
        self.servicer.users["existinguser"] = User("existinguser")
        req = message_service_pb2.UsernameRequest(username="existinguser")
        resp = self.servicer.CheckUsername(req, self.ctx)
        self.assertTrue(resp.exists)
        self.assertEqual(resp.message, "Account exists")

    def test_create_account_success(self):
        req = message_service_pb2.CreateAccountRequest(username="newuser", hashed_password="hashedpass")
        resp = self.servicer.CreateAccount(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.username, "newuser")
        self.assertEqual(resp.unread_count, 0)
        self.assertIn("newuser", self.servicer.users)
        self.assertIn("newuser", self.servicer.message_queues)

    def test_create_account_duplicate(self):
        self.servicer.users["existinguser"] = User("existinguser")
        req = message_service_pb2.CreateAccountRequest(username="existinguser", hashed_password="hashedpass")
        resp = self.servicer.CreateAccount(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Account already exists")

    def test_login_success(self):
        user = User("testuser", password="hashedpass")
        self.servicer.users["testuser"] = user
        req = message_service_pb2.LoginRequest(username="testuser", hashed_password="hashedpass")
        resp = self.servicer.Login(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.username, "testuser")
        self.assertEqual(resp.unread_count, user.undelivered_messages.qsize())

    def test_login_wrong_password(self):
        user = User("testuser", password="hashedpass")
        self.servicer.users["testuser"] = user
        req = message_service_pb2.LoginRequest(username="testuser", hashed_password="wrongpass")
        resp = self.servicer.Login(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Incorrect password")

    def test_login_nonexistent_user(self):
        req = message_service_pb2.LoginRequest(username="nonexistent", hashed_password="pass")
        resp = self.servicer.Login(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Account does not exist")

    def test_logout_success(self):
        self.servicer.users["testuser"] = User("testuser")
        self.servicer.active_users["testuser"] = self.ctx
        req = message_service_pb2.UsernameRequest(username="testuser")
        resp = self.servicer.Logout(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.message, "Logout successful")
        self.assertNotIn("testuser", self.servicer.active_users)

    def test_logout_not_logged_in(self):
        self.servicer.users["testuser"] = User("testuser")
        req = message_service_pb2.UsernameRequest(username="testuser")
        resp = self.servicer.Logout(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "User not logged in")

    def test_delete_account_success(self):
        user = User("testuser")
        self.servicer.users["testuser"] = user
        self.servicer.active_users["testuser"] = self.ctx
        req = message_service_pb2.UsernameRequest(username="testuser")
        resp = self.servicer.DeleteAccount(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.message, "Account deleted successfully")
        self.assertNotIn("testuser", self.servicer.users)
        self.assertNotIn("testuser", self.servicer.active_users)

    def test_delete_account_with_unread_messages(self):
        user = User("testuser")
        user.queue_message("Unread message")
        self.servicer.users["testuser"] = user
        req = message_service_pb2.UsernameRequest(username="testuser")
        resp = self.servicer.DeleteAccount(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Cannot delete account with unread messages")
        self.assertIn("testuser", self.servicer.users)

    def test_delete_nonexistent_account(self):
        req = message_service_pb2.UsernameRequest(username="nonexistent")
        resp = self.servicer.DeleteAccount(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Account does not exist")

    # --- Account Listing Tests ---
    def test_list_accounts_authenticated(self):
        self.servicer.users = {
            "alice": User("alice"),
            "bob": User("bob"),
            "carol": User("carol")
        }
        req = message_service_pb2.ListAccountsRequest(username="alice", pattern="*")
        resp = self.servicer.ListAccounts(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertIn("alice", resp.accounts)
        self.assertIn("bob", resp.accounts)
        self.assertIn("carol", resp.accounts)
        self.assertEqual(resp.message, "Found 3 matching accounts")

    def test_list_accounts_not_authenticated(self):
        req = message_service_pb2.ListAccountsRequest(username="nonexistent", pattern="*")
        resp = self.servicer.ListAccounts(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "User not authenticated")

    def test_list_accounts_no_matches(self):
        self.servicer.users = {
            "alice": User("alice"),
            "bob": User("bob")
        }
        req = message_service_pb2.ListAccountsRequest(username="alice", pattern="carol*")
        resp = self.servicer.ListAccounts(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(len(resp.accounts), 0)
        self.assertEqual(resp.message, "Found 0 matching accounts")

    # --- Message Management Tests ---
    def test_send_message_active_recipient(self):
        sender = "sender"
        receiver = "receiver"
        self.servicer.users[sender] = User(sender)
        receiver_user = User(receiver)
        self.servicer.users[receiver] = receiver_user
        # Ensure a message queue exists for the receiver.
        self.servicer.message_queues[receiver] = Queue()
        # Simulate the recipient being active.
        self.servicer.active_users[receiver] = self.ctx
        req = message_service_pb2.SendMessageRequest(sender=sender, recipient=receiver, content="Hello!")
        resp = self.servicer.SendMessage(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertIn("From sender", receiver_user.read_messages[0])
        self.assertIn("Hello!", receiver_user.read_messages[0])

    def test_send_message_offline_recipient(self):
        sender = "sender"
        receiver = "receiver"
        self.servicer.users[sender] = User(sender)
        receiver_user = User(receiver)
        self.servicer.users[receiver] = receiver_user
        # Ensure the message queue exists even if recipient is offline.
        self.servicer.message_queues[receiver] = Queue()
        req = message_service_pb2.SendMessageRequest(sender=sender, recipient=receiver, content="Hello!")
        resp = self.servicer.SendMessage(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertFalse(receiver_user.undelivered_messages.empty())

    def test_send_message_nonexistent_receiver(self):
        self.servicer.users["sender"] = User("sender")
        req = message_service_pb2.SendMessageRequest(sender="sender", recipient="nonexistent", content="Hello!")
        resp = self.servicer.SendMessage(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "Recipient not found")

    def test_view_messages_success(self):
        username = "testuser"
        user = User(username)
        user.queue_message("From sender at 2025-02-26 12:00:00: Hello")
        user.queue_message("From sender at 2025-02-26 12:01:00: Hi again")
        self.servicer.users[username] = user
        req = message_service_pb2.ViewMessagesRequest(username=username, count=2)
        resp = self.servicer.ViewMessages(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(len(resp.messages), 2)
        self.assertEqual(resp.message, "2 messages delivered")

    def test_view_messages_no_messages(self):
        username = "testuser"
        self.servicer.users[username] = User(username)
        req = message_service_pb2.ViewMessagesRequest(username=username, count=1)
        resp = self.servicer.ViewMessages(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "No undelivered messages")

    # --- Delete Messages Tests ---
    def test_delete_messages_all(self):
        username = "testuser"
        user = User(username)
        user.add_read_message("Message 1")
        user.add_read_message("Message 2")
        self.servicer.users[username] = user
        req = message_service_pb2.DeleteMessagesRequest(username=username, delete_info="ALL")
        resp = self.servicer.DeleteMessages(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.message, "Deleted 2 messages")
        self.assertEqual(len(user.read_messages), 0)

    def test_delete_messages_count(self):
        username = "testuser"
        user = User(username)
        for i in range(5):
            user.add_read_message(f"Message {i}")
        self.servicer.users[username] = user
        req = message_service_pb2.DeleteMessagesRequest(username=username, delete_info="3")
        resp = self.servicer.DeleteMessages(req, self.ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.message, "Deleted 3 messages")
        self.assertEqual(len(user.read_messages), 2)

    def test_delete_messages_invalid_count(self):
        username = "testuser"
        user = User(username)
        user.add_read_message("Message")
        self.servicer.users[username] = user
        req = message_service_pb2.DeleteMessagesRequest(username=username, delete_info="invalid")
        resp = self.servicer.DeleteMessages(req, self.ctx)
        self.assertFalse(resp.success)
        self.assertEqual(resp.message, "No messages deleted")

    # --- Receive Messages (Streaming) Test ---
    def test_receive_messages_stream(self):
        username = "testuser"
        user = User(username)
        self.servicer.users[username] = user
        timestamp = "2025-02-26 12:00:00"
        dummy_msg = message_service_pb2.MessageResponse(sender="sender", content="Hello", timestamp=timestamp)
        self.servicer.message_queues[username] = Queue()
        self.servicer.message_queues[username].put(dummy_msg)
        # Define a short-lived dummy context for streaming.
        class ShortLivedContext(DummyContext):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def is_active(self):
                self.calls += 1
                return self.calls < 5

        short_ctx = ShortLivedContext()
        req = message_service_pb2.UsernameRequest(username=username)
        messages = list(self.servicer.ReceiveMessages(req, short_ctx))
        self.assertGreater(len(messages), 0)
        self.assertEqual(messages[0].sender, "sender")
        self.assertEqual(messages[0].content, "Hello")
        self.assertEqual(messages[0].timestamp, timestamp)

if __name__ == '__main__':
    unittest.main()