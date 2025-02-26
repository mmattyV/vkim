import unittest
from queue import Queue
import sys
import os
import threading
from unittest.mock import Mock, patch
import socket
import struct

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.server import WireServer
from common.user import User
from common.operations import Operations
from common.serialization import serialize_custom, deserialize_custom

class DummyConnection:
    def __init__(self):
        self.sent_data = []
        self.closed = False
    
    def send(self, data):
        self.sent_data.append(data)
        
    def close(self):
        self.closed = True

class TestWireServer(unittest.TestCase):
    def setUp(self):
        """Set up test environment before each test"""
        self.server = WireServer()
        self.server.USERS = {}
        self.server.ACTIVE_USERS = {}
        self.dummy_conn = DummyConnection()
        
    def tearDown(self):
        """Clean up after each test"""
        self.server.USERS.clear()
        self.server.ACTIVE_USERS.clear()

    # Account Management Tests
    def test_check_username_nonexistent(self):
        """Test checking a username that doesn't exist"""
        result = self.server.check_username("newuser")
        self.assertEqual(result["operation"], Operations.ACCOUNT_DOES_NOT_EXIST)

    def test_check_username_exists(self):
        """Test checking a username that exists"""
        self.server.USERS["existinguser"] = User("existinguser")
        result = self.server.check_username("existinguser")
        self.assertEqual(result["operation"], Operations.ACCOUNT_ALREADY_EXISTS)

    def test_create_account_success(self):
        """Test successful account creation"""
        result = self.server.create_account("newuser", "hashedpass", self.dummy_conn)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("newuser", self.server.USERS)
        self.assertEqual(self.server.USERS["newuser"].password, "hashedpass")
        self.assertEqual(self.server.ACTIVE_USERS["newuser"], self.dummy_conn)

    def test_create_account_duplicate(self):
        """Test creating account with existing username"""
        self.server.USERS["existinguser"] = User("existinguser")
        result = self.server.create_account("existinguser", "hashedpass", self.dummy_conn)
        self.assertEqual(result["operation"], Operations.ACCOUNT_ALREADY_EXISTS)

    def test_login_success(self):
        """Test successful login"""
        user = User("testuser", password="hashedpass")
        self.server.USERS["testuser"] = user
        result = self.server.login("testuser", "hashedpass", self.dummy_conn)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("testuser", self.server.ACTIVE_USERS)

    def test_login_wrong_password(self):
        """Test login with incorrect password"""
        user = User("testuser", password="hashedpass")
        self.server.USERS["testuser"] = user
        result = self.server.login("testuser", "wrongpass", self.dummy_conn)
        self.assertEqual(result["operation"], Operations.FAILURE)

    def test_login_nonexistent_user(self):
        """Test login with non-existent username"""
        result = self.server.login("nonexistent", "pass", self.dummy_conn)
        self.assertEqual(result["operation"], Operations.FAILURE)

    def test_logout_success(self):
        """Test successful logout"""
        self.server.USERS["testuser"] = User("testuser")
        self.server.ACTIVE_USERS["testuser"] = self.dummy_conn
        result = self.server.logout("testuser")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertNotIn("testuser", self.server.ACTIVE_USERS)

    def test_logout_not_logged_in(self):
        """Test logout when user isn't logged in"""
        self.server.USERS["testuser"] = User("testuser")
        result = self.server.logout("testuser")
        self.assertEqual(result["operation"], Operations.ACCOUNT_DOES_NOT_EXIST)

    # Message Management Tests
    def test_send_message_to_active_user(self):
        """Test sending message to online user"""
        sender = "sender"
        receiver = "receiver"
        self.server.USERS[sender] = User(sender)
        self.server.USERS[receiver] = User(receiver)
        self.server.ACTIVE_USERS[receiver] = self.dummy_conn
        
        result = self.server.send_message(sender, receiver, "Hello!")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("From sender: Hello!", self.server.USERS[receiver].read_messages)

    def test_send_message_to_offline_user(self):
        """Test sending message to offline user"""
        sender = "sender"
        receiver = "receiver"
        self.server.USERS[sender] = User(sender)
        self.server.USERS[receiver] = User(receiver)
        
        result = self.server.send_message(sender, receiver, "Hello!")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertFalse(self.server.USERS[receiver].undelivered_messages.empty())

    def test_send_message_to_nonexistent_user(self):
        """Test sending message to non-existent user"""
        result = self.server.send_message("sender", "nonexistent", "Hello!")
        self.assertEqual(result["operation"], Operations.FAILURE)

    def test_view_messages_success(self):
        """Test viewing messages successfully"""
        username = "testuser"
        user = User(username)
        user.queue_message("Message 1")
        user.queue_message("Message 2")
        self.server.USERS[username] = user
        
        result = self.server.view_msgs(username, 2)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("Message 1", result["info"][0])
        self.assertIn("Message 2", result["info"][0])

    def test_view_messages_no_messages(self):
        """Test viewing messages when there are none"""
        username = "testuser"
        self.server.USERS[username] = User(username)
        result = self.server.view_msgs(username, 1)
        self.assertEqual(result["operation"], Operations.FAILURE)

    def test_view_messages_partial_count(self):
        """Test viewing fewer messages than available"""
        username = "testuser"
        user = User(username)
        for i in range(5):
            user.queue_message(f"Message {i}")
        self.server.USERS[username] = user
        
        result = self.server.view_msgs(username, 3)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        messages = result["info"][0].split("\n")
        self.assertEqual(len(messages), 3)

    def test_delete_messages_all(self):
        """Test deleting all messages"""
        username = "testuser"
        user = User(username)
        user.add_read_message("Message 1")
        user.add_read_message("Message 2")
        self.server.USERS[username] = user
        
        result = self.server.delete_message(username, "ALL")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertEqual(len(self.server.USERS[username].read_messages), 0)

    def test_delete_messages_count(self):
        """Test deleting specific number of messages"""
        username = "testuser"
        user = User(username)
        for i in range(5):
            user.add_read_message(f"Message {i}")
        self.server.USERS[username] = user
        
        result = self.server.delete_message(username, "3")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertEqual(len(self.server.USERS[username].read_messages), 2)

    def test_delete_messages_invalid_count(self):
        """Test deleting messages with invalid count"""
        username = "testuser"
        user = User(username)
        user.add_read_message("Message")
        self.server.USERS[username] = user
        
        result = self.server.delete_message(username, "invalid")
        self.assertEqual(result["operation"], Operations.FAILURE)

    # Account Listing Tests
    def test_list_accounts_all(self):
        """Test listing all accounts"""
        self.server.USERS = {
            "user1": User("user1"),
            "user2": User("user2"),
            "user3": User("user3")
        }
        result = self.server.list_accounts("*")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("user1", result["info"][0])
        self.assertIn("user2", result["info"][0])
        self.assertIn("user3", result["info"][0])

    def test_list_accounts_pattern(self):
        """Test listing accounts matching pattern"""
        self.server.USERS = {
            "test1": User("test1"),
            "test2": User("test2"),
            "other": User("other")
        }
        result = self.server.list_accounts("test*")
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertIn("test1", result["info"][0])
        self.assertIn("test2", result["info"][0])
        self.assertNotIn("other", result["info"][0])

    def test_list_accounts_no_matches(self):
        """Test listing accounts with no matches"""
        self.server.USERS = {
            "user1": User("user1"),
            "user2": User("user2")
        }
        result = self.server.list_accounts("nonexistent*")
        self.assertEqual(result["operation"], Operations.FAILURE)

    # Delete Account Tests
    def test_delete_account_success(self):
        """Test successful account deletion"""
        username = "testuser"
        user = User(username)
        self.server.USERS[username] = user
        self.server.ACTIVE_USERS[username] = self.dummy_conn
        
        result = self.server.delete_account(username)
        self.assertEqual(result["operation"], Operations.SUCCESS)
        self.assertNotIn(username, self.server.USERS)
        self.assertNotIn(username, self.server.ACTIVE_USERS)

    def test_delete_account_with_messages(self):
        """Test deleting account with unread messages"""
        username = "testuser"
        user = User(username)
        user.queue_message("Unread message")
        self.server.USERS[username] = user
        
        result = self.server.delete_account(username)
        self.assertEqual(result["operation"], Operations.FAILURE)
        self.assertIn(username, self.server.USERS)

    def test_delete_nonexistent_account(self):
        """Test deleting non-existent account"""
        result = self.server.delete_account("nonexistent")
        self.assertEqual(result["operation"], Operations.ACCOUNT_DOES_NOT_EXIST)

    # Connection Management Tests
    def test_recvall_complete_data(self):
        """Test receiving complete data"""
        mock_conn = Mock()
        mock_conn.recv.side_effect = [b"1234", b"5678"]
        result = self.server.recvall(mock_conn, 8)
        self.assertEqual(result, b"12345678")

    def test_recvall_incomplete_data(self):
        """Test receiving incomplete data"""
        mock_conn = Mock()
        mock_conn.recv.side_effect = [b"1234", b""]
        result = self.server.recvall(mock_conn, 8)
        self.assertEqual(result, b"1234")

    def test_recvall_connection_error(self):
        """Test receiving data with connection error"""
        mock_conn = Mock()
        mock_conn.recv.side_effect = Exception("Connection error")
        result = self.server.recvall(mock_conn, 8)
        self.assertEqual(result, b"")

    # Concurrent Operation Tests
    def test_concurrent_message_send(self):
        """Test sending messages concurrently"""
        receiver = "receiver"
        self.server.USERS[receiver] = User(receiver)
        
        def send_message(sender_id):
            return self.server.send_message(f"sender{sender_id}", receiver, f"Message {sender_id}")
            
        threads = []
        results = []
        for i in range(10):
            thread = threading.Thread(target=lambda: results.append(send_message(i)))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join()
            
        self.assertTrue(all(r["operation"] == Operations.SUCCESS for r in results))
        self.assertEqual(self.server.USERS[receiver].undelivered_messages.qsize(), 10)

if __name__ == '__main__':
    unittest.main()