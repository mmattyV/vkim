# persistence.py

import pickle    # For serializing and deserializing Python objects to/from binary files
import os        # For interacting with the operating system (e.g., checking file existence)
import socket    # For obtaining the hostname of the current machine

def get_state_file(port):
    """
    Generate a filename for storing server state based on the hostname and provided port.
    
    Args:
        port (int): The port number associated with the server.
    
    Returns:
        str: The filename for the state file.
    """
    # Get the current machine's hostname.
    hostname = socket.gethostname()
    # Create a unique state file name using the hostname and port.
    return f"server_state_{hostname}_{port}.pkl"

def load_state(port):
    """
    Load the server state from a pickle file for the given port.
    
    If the file exists, deserialize and return the state.
    If the file does not exist, return a default initial state.
    
    Args:
        port (int): The port number associated with the server.
    
    Returns:
        dict: The server state.
    """
    # Determine the state file path based on the port.
    state_file = get_state_file(port)
    
    # Check if the state file exists.
    if os.path.exists(state_file):
        # Open the file in binary read mode and load the state using pickle.
        with open(state_file, "rb") as f:
            return pickle.load(f)
    else:
        # Return a default initial state if no state file exists.
        return {
            "users": {},             # Dictionary to hold user information.
            "message_queues": {},    # Dictionary to store messages per user: {username: list_of_messages}.
            "replication_log": set() # Set to record replication events or logs.
        }

def save_state(state, port):
    """
    Save the server state to a pickle file for the given port.
    
    Args:
        state (dict): The server state to be saved.
        port (int): The port number associated with the server.
    """
    # Determine the state file path based on the port.
    state_file = get_state_file(port)
    
    # Open the file in binary write mode and serialize the state using pickle.
    with open(state_file, "wb") as f:
        pickle.dump(state, f)