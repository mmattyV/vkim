import io
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch, MagicMock
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "client")))

# Import the client code and required enums.
# (Make sure your PYTHONPATH is set appropriately or run tests from the project root.)
from client import ChatClient
from operations import Operations


# A dummy socket that records data “sent” by the client.
class DummySocket:
    def __init__(self):
        self.sent_data = []

    def sendall(self, data):
        self.sent_data.append(data)

    def close(self):
        pass

    # We add a dummy recv method for tests that might invoke receive logic.
    def recv(self, n):
        return b''


class TestChatClientSendAndConnect(unittest.TestCase):
    def setUp(self):
        self.client = ChatClient()
        # Instead of creating a real socket, use a dummy
        self.client.sock = DummySocket()

    @patch('client.serialize_custom')
    def test_send_message_calls_socket_sendall(self, mock_serialize):
        """Test that send_message serializes the data and calls sendall."""
        # Arrange: have the serialization function return known bytes.
        mock_serialize.return_value = b'serialized-data'
        op = Operations.SEND_MESSAGE
        payload = ["Hello, world!"]

        # Act: call send_message.
        self.client.send_message(op, payload)

        # Assert: the dummy socket should have recorded the call.
        self.assertIn(b'serialized-data', self.client.sock.sent_data)
        mock_serialize.assert_called_once_with(op, payload)

    @patch('socket.socket')
    def test_connect_failure(self, mock_socket_class):
        """Test that a connection failure results in sys.exit(1)."""
        # Arrange: make the socket’s connect method raise an exception.
        instance = mock_socket_class.return_value
        instance.connect.side_effect = Exception("Connection error")

        with self.assertRaises(SystemExit):
            self.client.connect()


class TestChatClientHandleResponse(unittest.TestCase):
    def setUp(self):
        self.client = ChatClient()
        # We do not need a real socket in these tests.
        self.client.sock = DummySocket()

    def test_handle_create_account_success(self):
        """Test that a SUCCESS response during account creation updates state."""
        # Set the current operation so that the response is processed.
        self.client.current_operation = 'create_account'
        self.client.create_account_event.clear()

        # Simulate the server sending a SUCCESS response with payload:
        # [username, message, number_of_unread_messages]
        username = "testuser"
        payload = [username, "Account created successfully", "0"]
        # Call handle_server_response with the msg_type equal to Operations.SUCCESS
        self.client.handle_server_response(Operations.SUCCESS.value, payload)

        # Check that the username was set and the event is flagged.
        self.assertEqual(self.client.username, username)
        self.assertEqual(self.client.number_unread_messages, 0)
        self.assertTrue(self.client.create_account_event.is_set())

    def test_handle_check_username_does_not_exist(self):
        """Test that a CHECK_USERNAME response for a non‐existent account sets the event."""
        self.client.current_operation = 'check_username'
        self.client.check_username_event.clear()

        # Simulate server response indicating that the account does not exist.
        self.client.handle_server_response(Operations.ACCOUNT_DOES_NOT_EXIST.value, [])

        self.assertEqual(self.client.account_exists_response, Operations.ACCOUNT_DOES_NOT_EXIST)
        self.assertTrue(self.client.check_username_event.is_set())

    def test_handle_no_operation_pending(self):
        """If no current operation is pending, a response should not cause an error."""
        self.client.current_operation = None

        with patch('sys.stdout', new=io.StringIO()) as fake_output:
            # Call with any operation (here, SUCCESS) and a dummy payload.
            self.client.handle_server_response(Operations.SUCCESS.value, ["dummy"])
            self.assertIn("No operation is currently awaiting a response", fake_output.getvalue())

    def test_handle_login_success(self):
        """Test that a successful login response updates state."""
        self.client.current_operation = 'login'
        self.client.login_event.clear()

        # Simulate a login SUCCESS response with payload:
        # [username, message, number_of_unread_messages]
        username = "loggedinuser"
        payload = [username, "Login successful", "3"]
        self.client.handle_server_response(Operations.SUCCESS.value, payload)

        self.assertEqual(self.client.username, username)
        self.assertEqual(self.client.number_unread_messages, 3)
        self.assertTrue(self.client.login_event.is_set())


class TestChatClientInteractiveMethods(unittest.TestCase):
    def setUp(self):
        self.client = ChatClient()
        # Replace the socket with a dummy so that calls to send_message do not error.
        self.client.sock = DummySocket()

    @patch('builtins.input', side_effect=[''])  # Simulate empty username input.
    def test_try_create_account_empty_username(self, mock_input):
        """Test that try_create_account prints a message if username is empty."""
        with patch('sys.stdout', new=io.StringIO()) as fake_output:
            self.client.try_create_account()
            self.assertIn("Username cannot be empty", fake_output.getvalue())

    def test_send_chat_message_without_login(self):
        """Test that attempting to send a message without logging in prints an error."""
        with patch('builtins.input', side_effect=['recipient', 'Hello']):
            with patch('sys.stdout', new=io.StringIO()) as fake_output:
                # Make sure username is None.
                self.client.username = None
                self.client.send_chat_message()
                self.assertIn("You must be logged in to send messages", fake_output.getvalue())

    @patch('builtins.input', side_effect=['recipient', 'Hello'])
    def test_send_chat_message_logged_in_success(self, mock_input):
        """Test that send_chat_message calls send_message when the user is logged in.
        
        To avoid waiting for the event (which normally uses a timeout), we override
        the event’s wait method to return immediately.
        """
        # Set a logged-in username.
        self.client.username = "testuser"
        # Override the event wait so that it returns True immediately.
        self.client.send_message_event.wait = lambda timeout: True
        # Set the response so that the method will treat it as a success.
        self.client.send_message_response = Operations.SUCCESS
        # Replace send_message with a MagicMock so we can inspect its call.
        self.client.send_message = MagicMock()

        self.client.send_chat_message()

        # Check that send_message was called (once) with the SEND_MESSAGE operation.
        self.client.send_message.assert_called_once()
        args, kwargs = self.client.send_message.call_args
        self.assertEqual(args[0], Operations.SEND_MESSAGE)
        # The payload should be a string that contains the sender’s username.
        self.assertIn("testuser", args[1][0])

if __name__ == '__main__':
    unittest.main()
