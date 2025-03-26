import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

from user import User  # Assuming the User class is in common/user.py

class TestUser(unittest.TestCase):

    def setUp(self):
        """Set up a User instance for testing."""
        self.user = User("test_user", "hashed_password")

    def test_initialization(self):
        """Test that the User is initialized correctly."""
        self.assertEqual(self.user.username, "test_user")
        self.assertEqual(self.user.password, "hashed_password")
        self.assertTrue(self.user.undelivered_messages.empty())
        self.assertEqual(self.user.read_messages, [])

    def test_queue_message(self):
        """Test queuing a message for later delivery."""
        self.user.queue_message("Hello, World!")
        self.assertFalse(self.user.undelivered_messages.empty())
        self.assertEqual(self.user.undelivered_messages.qsize(), 1)

    def test_get_current_messages(self):
        """Test retrieving undelivered messages and marking them as read."""
        self.user.queue_message("Message 1")
        self.user.queue_message("Message 2")
        messages = self.user.get_current_messages(1)
        self.assertEqual(messages, ["Message 1"])
        self.assertEqual(len(self.user.read_messages), 1)
        self.assertEqual(self.user.read_messages[0], "Message 1")
        self.assertEqual(self.user.undelivered_messages.qsize(), 1)

    def test_get_current_messages_more_than_available(self):
        """Test retrieving more messages than are available."""
        self.user.queue_message("Only message")
        messages = self.user.get_current_messages(3)
        self.assertEqual(messages, ["Only message"])
        self.assertTrue(self.user.undelivered_messages.empty())
        self.assertEqual(len(self.user.read_messages), 1)

    def test_add_read_message(self):
        """Test marking a message as read."""
        self.user.add_read_message("Read message")
        self.assertIn("Read message", self.user.read_messages)

    def test_delete_read_messages_all(self):
        """Test deleting all read messages."""
        self.user.add_read_message("Message 1")
        self.user.add_read_message("Message 2")
        deleted_count = self.user.delete_read_messages("ALL")
        self.assertEqual(deleted_count, 2)
        self.assertEqual(self.user.read_messages, [])

    def test_delete_read_messages_partial(self):
        """Test deleting a specific number of read messages."""
        self.user.add_read_message("Message 1")
        self.user.add_read_message("Message 2")
        self.user.add_read_message("Message 3")
        deleted_count = self.user.delete_read_messages("2")
        self.assertEqual(deleted_count, 2)
        self.assertEqual(self.user.read_messages, ["Message 3"])

    def test_delete_read_messages_invalid_input(self):
        """Test deletion with an invalid input (should return 0 deletions)."""
        self.user.add_read_message("Message 1")
        deleted_count = self.user.delete_read_messages("INVALID")
        self.assertEqual(deleted_count, 0)
        self.assertEqual(len(self.user.read_messages), 1)

if __name__ == "__main__":
    unittest.main()