# test_server.py

import unittest
from queue import Queue
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.server import WireServer
from user import User
from operations import Operations

# A simple dummy connection that collects any data "sent" to it.
class DummyConnection:
    def __init__(self):
        self.sent_data = []
    def send(self, data):
        self.sent_data.append(data)

class TestWireServerBusinessLogic(unittest.TestCase):
    def setUp(self):
        # Create a new WireServer instance.
        self.server = WireServer()
        # Reset the USERS and ACTIVE_USERS dictionaries before each test.
        self.server.USERS = {}
        self.server.ACTIVE_USERS = {}
        # Create a dummy connection for testing.
        self.dummy_conn = DummyConnection()

    def test_create_account_success(self):
        username = "testuser"
        result = self.server.create_account(username, self.dummy_conn)
        # Check that the operation in the payload indicates success.
        self.assertEqual(result["operation"], Operations.SUCCESS)
        # Verify that the new user is added to USERS and ACTIVE_USERS.
        self.assertIn(username, self.server.USERS)
        self.assertIn(username, self.server.ACTIVE_USERS)

    def test_create_account_already_exists(self):
        username = "testuser"
        # Create the account once.
        self.server.create_account(username, self.dummy_conn)
        # Try creating it again.
        result = self.server.create_account(username, self.dummy_conn)
        self.assertEqual(result["operation"], Operations.ACCOUNT_ALREADY_EXISTS)

    def test_login_success(self):
        username = "loginuser"
        # Pre-create the user.
        self.server.USERS[username] = User(username)
        result = self.server.login(username, self.dummy_conn)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn(username, self.server.ACTIVE_USERS)

    def test_login_failure(self):
        username = "nonexistent"
        result = self.server.login(username, self.dummy_conn)
        self.assertEqual(result["operation"], Operations.ACCOUNT_DOES_NOT_EXIST)

    def test_logout_success(self):
        username = "logoutuser"
        # Pre-create and mark as active.
        self.server.USERS[username] = User(username)
        self.server.ACTIVE_USERS[username] = self.dummy_conn
        result = self.server.logout(username)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertNotIn(username, self.server.ACTIVE_USERS)

    def test_logout_failure(self):
        username = "nonexistent"
        result = self.server.logout(username)
        self.assertEqual(result["operation"], Operations.ACCOUNT_DOES_NOT_EXIST)

    # def test_send_message_offline(self):
    #     sender = "sender"
    #     receiver = "receiver"
    #     msg = "Hello offline"
    #     # Pre-create sender and receiver, but do not mark receiver as active.
    #     self.server.USERS[sender] = User(sender)
    #     self.server.USERS[receiver] = User(receiver)
    #     result = self.server.send_message(sender, receiver, msg)
    #     self.assertEqual(result["operation"], Operations.SUCCESS)
    #     # The message should be queued in the receiver's undelivered_messages.
    #     queued_messages = self.server.USERS[receiver].get_current_messages()
    #     self.assertIn(f"From {sender}: {msg}", queued_messages)

    # def test_send_message_active(self):
    #     sender = "sender"
    #     receiver = "receiver"
    #     msg = "Hello active"
    #     # Pre-create sender and receiver.
    #     self.server.USERS[sender] = User(sender)
    #     self.server.USERS[receiver] = User(receiver)
    #     # Mark receiver as active by providing a dummy connection.
    #     dummy_conn_receiver = DummyConnection()
    #     self.server.ACTIVE_USERS[receiver] = dummy_conn_receiver
    #     result = self.server.send_message(sender, receiver, msg)
    #     self.assertEqual(result["operation"], Operations.SUCCESS)
    #     # For an active receiver, the message should be delivered immediately rather than queued.
    #     # (This may depend on how your immediate delivery is implemented.)
    #     self.assertTrue(self.server.USERS[receiver].undelivered_messages.empty())

    # def test_view_msgs_empty(self):
    #     username = "nomsg"
    #     self.server.USERS[username] = User(username)
    #     result = self.server.view_msgs(username)
    #     self.assertEqual(result["operation"], Operations.FAILURE)

    # def test_view_msgs_success(self):
    #     username = "hasmsg"
    #     user = User(username)
    #     user.queue_message("Test message")
    #     self.server.USERS[username] = user
    #     result = self.server.view_msgs(username)
    #     self.assertEqual(result["operation"], Operations.SUCCESS)
    #     self.assertIn("Test message", result["info"])

if __name__ == "__main__":
    import unittest
    unittest.main()