import unittest
from unittest.mock import patch, MagicMock, call
import socket
import threading
import struct
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "client")))

from operations import Operations
from serialization import serialize_custom
from client import ChatClient

class TestChatClient(unittest.TestCase):

    def setUp(self):
        # Start patching 'client.socket.socket'
        patcher = patch('client.socket.socket')
        self.addCleanup(patcher.stop)  # Ensure that patcher stops after each test
        self.mock_socket_class = patcher.start()
        
        # Create a mock socket instance
        self.mock_socket = MagicMock()
        self.mock_socket_class.return_value = self.mock_socket

        # Initialize the ChatClient with mocked socket
        self.client = ChatClient(host='localhost', port=12345)

    def tearDown(self):
        # Ensure the socket is closed after each test to prevent ResourceWarnings
        self.client.close()

    @patch('client.threading.Thread')
    def test_connect_success(self, mock_thread_class):
        # Simulate successful connection by ensuring connect does not raise
        # Mock the thread to prevent actual threading
        mock_thread = MagicMock()
        mock_thread_class.return_value = mock_thread

        # Perform the connection
        self.client.connect()

        # Verify that socket.connect was called with correct parameters
        self.mock_socket.connect.assert_called_with(('localhost', 12345))
        self.assertTrue(self.client.running)
        self.assertIsNotNone(self.client.receive_thread)

        # Verify that the receive thread was started
        mock_thread.start.assert_called_once()

    @patch('client.threading.Thread')
    def test_connect_failure(self, mock_thread_class):
        # Simulate connection failure by having connect() raise an exception
        self.mock_socket.connect.side_effect = socket.error("Connection failed")

        # Patch sys.exit to prevent the test runner from exiting
        with patch('client.sys.exit') as mock_exit, \
             patch('builtins.print') as mock_print:
            self.client.connect()

            # Verify that socket.connect was called
            self.mock_socket.connect.assert_called_with(('localhost', 12345))

            # Verify that an error message was printed
            mock_print.assert_called_with("Failed to connect to server: Connection failed")

            # Verify that sys.exit was called with code 1
            mock_exit.assert_called_with(1)

            # Ensure that running is still False
            self.assertFalse(self.client.running)

    def test_send_message(self):
        # Prepare test data
        msg_type = Operations.LOGIN
        payload = ['user1', 'password123']
        serialized = serialize_custom(msg_type, payload)

        # Send message
        self.client.sock = self.mock_socket  # Manually set the socket
        self.client.send_message(msg_type, payload)

        # Verify that the correct data was sent
        self.mock_socket.sendall.assert_called_with(serialized)
        print(f"Sent {msg_type.name} with payload: {payload}")

    @patch('client.ChatClient.handle_server_response')
    def test_receive_messages(self, mock_handle_response):
        # Prepare a serialized message to simulate server response
        msg_type = Operations.SUCCESS
        payload = ['Login successful', '5']  # Example payload
        serialized = serialize_custom(msg_type, payload)

        # The client expects header + payload, as per deserialize_custom
        self.mock_socket.recv.side_effect = [
            serialized[:8],               # Header
            serialized[8:],               # Payload
            b''                           # No more data, simulate server closing
        ]

        # Start receive_messages in a separate thread
        self.client.sock = self.mock_socket
        self.client.running = True

        # Since receive_messages runs in a separate thread, we'll run it synchronously for testing
        self.client.receive_messages()

        # Verify that handle_server_response was called correctly
        mock_handle_response.assert_called_with(msg_type, payload)
        print(f"Received {msg_type.name} with payload: {payload}")

    @patch('client.ChatClient.handle_server_response')
    def test_receive_incomplete_payload(self, mock_handle_response):
        # Prepare an incomplete payload
        msg_type = Operations.SUCCESS
        payload = ['Incomplete']
        serialized = serialize_custom(msg_type, payload)
        incomplete_serialized = serialized[:10]  # Truncate payload

        self.mock_socket.recv.side_effect = [
            incomplete_serialized[:8],  # Header
            incomplete_serialized[8:],  # Incomplete payload
            b''                         # No more data
        ]

        # Start receive_messages in a separate thread
        self.client.sock = self.mock_socket
        self.client.running = True

        # Run receive_messages synchronously
        self.client.receive_messages()

        # handle_server_response should not be called due to incomplete payload
        mock_handle_response.assert_not_called()
        print("Incomplete payload received.")

    @patch('builtins.print')
    def test_handle_unknown_server_response(self, mock_print):
        # Test handling an unknown message type
        unknown_msg_type = 9999
        payload = ['Unknown operation']
        self.client.handle_server_response(unknown_msg_type, payload)

        # Verify that the appropriate message was printed
        mock_print.assert_called_with(f"Unknown message type received: {unknown_msg_type}, Payload: {payload}")

    @patch('builtins.print')
    def test_handle_known_server_response(self, mock_print):
        # Test handling a known message type
        msg_type = Operations.SUCCESS
        payload = ['Operation successful']
        self.client.handle_server_response(msg_type, payload)

        # Verify that the appropriate message was printed
        mock_print.assert_called_with(f"Server Response: SUCCESS, Payload: {payload}")

    @patch('builtins.input', side_effect=['testuser', 'testpass'])
    def test_create_account(self, mock_inputs):
        # Test the create_account method
        self.client.sock = self.mock_socket
        self.client.create_account()

        # Verify that send_message was called with CREATE_ACCOUNT and correct payload
        expected_payload = ['testuser', 'testpass']
        serialized = serialize_custom(Operations.CREATE_ACCOUNT, expected_payload)
        self.mock_socket.sendall.assert_called_with(serialized)
        print("Sent CREATE_ACCOUNT with payload: ['testuser', 'testpass']")

    @patch('builtins.input', side_effect=['loginuser', 'loginpass'])
    def test_log_in(self, mock_inputs):
        # Test the log_in method
        self.client.sock = self.mock_socket
        self.client.log_in()

        # Verify that send_message was called with LOGIN and correct payload
        expected_payload = ['loginuser', 'loginpass']
        serialized = serialize_custom(Operations.LOGIN, expected_payload)
        self.mock_socket.sendall.assert_called_with(serialized)
        print("Sent LOGIN with payload: ['loginuser', 'loginpass']")

    @patch('builtins.input', side_effect=['recipient', 'Hello!'])
    def test_send_chat_message(self, mock_inputs):
        # Test the send_chat_message method
        self.client.sock = self.mock_socket
        self.client.send_chat_message()

        # Verify that send_message was called with SEND_MESSAGE and correct payload
        expected_payload = ['recipient', 'Hello!']
        serialized = serialize_custom(Operations.SEND_MESSAGE, expected_payload)
        self.mock_socket.sendall.assert_called_with(serialized)
        print("Sent SEND_MESSAGE with payload: ['recipient', 'Hello!']")

    def test_logout(self):
        # Test the logout method
        self.client.sock = self.mock_socket
        self.client.logout()

        # Verify that send_message was called with LOGOUT and empty payload
        serialized = serialize_custom(Operations.LOGOUT, [])
        self.mock_socket.sendall.assert_called_with(serialized)
        print("Sent LOGOUT with payload: []")

if __name__ == '__main__':
    unittest.main()