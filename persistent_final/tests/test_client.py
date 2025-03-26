import io
import sys
import os
import threading
import unittest
from unittest.mock import patch, MagicMock

# Ensure the parent directory is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client.grpc_client import ChatClient

# A simple dummy response to simulate gRPC responses.
class DummyResponse:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class TestChatClientMethods(unittest.TestCase):

    def setUp(self):
        self.client = ChatClient()
        # Replace the stub with a MagicMock so we can control RPC responses.
        self.client.stub = MagicMock()

    @patch('builtins.input', side_effect=['testuser', 'testpassword'])
    def test_log_in_success(self, mock_input):
        """Test that a successful login updates client state."""
        dummy_resp = DummyResponse(success=True, username='testuser',
                                   unread_count=2, message="Login successful")
        self.client.stub.Login.return_value = dummy_resp

        self.client.log_in()

        self.assertEqual(self.client.username, 'testuser')
        self.assertEqual(self.client.number_unread_messages, 2)
        self.client.stub.Login.assert_called_once()

    @patch('builtins.input', side_effect=['testuser', 'testpassword'])
    def test_try_create_account_success(self, mock_input):
        """Test that try_create_account creates an account when it does not exist."""
        dummy_check = DummyResponse(exists=False, message="Username available")
        dummy_create = DummyResponse(success=True, username='testuser',
                                     unread_count=0, message="Account created successfully")
        self.client.stub.CheckUsername.return_value = dummy_check
        self.client.stub.CreateAccount.return_value = dummy_create

        # For try_create_account, the client first reads a username and then a password.
        with patch('builtins.input', side_effect=['testuser', 'testpassword']):
            self.client.try_create_account()

        self.assertEqual(self.client.username, 'testuser')
        self.client.stub.CheckUsername.assert_called_once()
        self.client.stub.CreateAccount.assert_called_once()

    @patch('builtins.input', side_effect=['*'])
    def test_list_accounts_success(self, mock_input):
        """Test that list_accounts prints matching accounts."""
        self.client.username = 'testuser'
        dummy_resp = DummyResponse(success=True, accounts=['user1', 'user2'], message="2 accounts found")
        self.client.stub.ListAccounts.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.list_accounts()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("Matching accounts:", output)
        self.assertIn("user1", output)
        self.assertIn("user2", output)

    @patch('builtins.input', side_effect=['recipientUser', 'Hello there'])
    def test_send_chat_message_success(self, mock_input):
        """Test that send_chat_message calls SendMessage RPC and prints its response."""
        self.client.username = 'testuser'
        dummy_resp = DummyResponse(success=True, message="Message sent for immediate delivery")
        self.client.stub.SendMessage.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.send_chat_message()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("Message sent", output)
        self.client.stub.SendMessage.assert_called_once()

    @patch('builtins.input', side_effect=['2'])
    def test_view_messages_success(self, mock_input):
        """Test that view_messages prints received messages."""
        self.client.username = 'testuser'
        dummy_message = DummyResponse(sender="user1", content="Hello",
                                      timestamp="2025-02-26 12:00:00")
        dummy_resp = DummyResponse(success=True, messages=[dummy_message],
                                   message="1 messages delivered")
        self.client.stub.ViewMessages.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.view_messages()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("From user1: Hello (at 2025-02-26 12:00:00)", output)

    @patch('builtins.input', side_effect=['ALL'])
    def test_delete_messages_success(self, mock_input):
        """Test that delete_messages prints the server’s confirmation."""
        self.client.username = 'testuser'
        dummy_resp = DummyResponse(success=True, message="Messages deleted successfully")
        self.client.stub.DeleteMessages.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.delete_messages()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("Messages deleted successfully", output)

    @patch('builtins.input', side_effect=['yes'])
    def test_delete_account_success(self, mock_input):
        """Test that delete_account clears the username on success."""
        self.client.username = 'testuser'
        dummy_resp = DummyResponse(success=True, message="Account deleted successfully")
        self.client.stub.DeleteAccount.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.delete_account()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("Account deleted successfully", output)
        self.assertIsNone(self.client.username)

    def test_logout_success(self):
        """Test that logout clears the username on success."""
        self.client.username = 'testuser'
        dummy_resp = DummyResponse(success=True, message="Logged out successfully")
        self.client.stub.Logout.return_value = dummy_resp

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.logout()

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("Logged out successfully", output)
        self.assertIsNone(self.client.username)

    def test_start_receiving(self):
        """Test that start_receiving starts a daemon thread and prints messages."""
        # Set a username so that start_receiving proceeds.
        self.client.username = 'testuser'
        # Create a dummy generator to simulate streaming messages.
        def dummy_stream(request):
            for i in range(2):
                dummy_msg = DummyResponse(sender="user1", content=f"Hello {i}", timestamp="2025-02-26 12:00:00")
                yield dummy_msg
        self.client.stub.ReceiveMessages.side_effect = dummy_stream

        captured_output = io.StringIO()
        sys.stdout = captured_output

        self.client.start_receiving()
        # Give some time for the background thread to process messages.
        threading.Event().wait(0.2)

        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        self.assertIn("[New Message from user1]: Hello 0", output)
        self.assertIn("[New Message from user1]: Hello 1", output)

if __name__ == '__main__':
    unittest.main()