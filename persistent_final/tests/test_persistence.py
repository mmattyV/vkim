import os
import pickle
import tempfile
import unittest
from unittest.mock import patch
import sys

# Ensure the persistence module is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")))

import persistence

class TestPersistence(unittest.TestCase):
    def setUp(self):
        # Patch socket.gethostname to always return 'testhost'
        patcher = patch('persistence.socket.gethostname', return_value='testhost')
        self.mock_gethostname = patcher.start()
        self.addCleanup(patcher.stop)

        # Create a temporary directory and change into it
        self.original_cwd = os.getcwd()
        self.temp_dir = tempfile.TemporaryDirectory()
        os.chdir(self.temp_dir.name)

    def tearDown(self):
        # Return to the original directory and clean up the temporary directory
        os.chdir(self.original_cwd)
        self.temp_dir.cleanup()

    def test_get_state_file(self):
        """Test that get_state_file returns a filename that includes the hostname and port."""
        port = 8080
        expected_filename = f"server_state_testhost_{port}.pkl"
        filename = persistence.get_state_file(port)
        self.assertEqual(filename, expected_filename)

    def test_load_state_default(self):
        """
        Test that load_state returns the default state when no state file exists.
        """
        port = 8080
        # Ensure that no state file exists in the temporary directory.
        state_file = persistence.get_state_file(port)
        if os.path.exists(state_file):
            os.remove(state_file)

        state = persistence.load_state(port)
        expected_state = {
            "users": {},
            "message_queues": {},
            "replication_log": set()
        }
        self.assertEqual(state, expected_state)

    def test_save_and_load_state(self):
        """
        Test that saving a state to file and then loading it returns the same state.
        """
        port = 8080
        test_state = {
            "users": {"user1": {"data": "some data"}},
            "message_queues": {"user1": ["Hello", "World"]},
            "replication_log": {1, 2, 3}
        }
        persistence.save_state(test_state, port)
        loaded_state = persistence.load_state(port)
        self.assertEqual(loaded_state, test_state)

if __name__ == '__main__':
    unittest.main()