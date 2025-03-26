# persistence.py
import pickle
import os
import socket

def get_state_file(port):
    hostname = socket.gethostname()
    return f"server_state_{hostname}_{port}.pkl"

def load_state(port):
    state_file = get_state_file(port)
    if os.path.exists(state_file):
        with open(state_file, "rb") as f:
            return pickle.load(f)
    else:
        # Return initial empty state
        return {
            "users": {},
            "message_queues": {},  # will be stored as {username: list_of_messages}
            "replication_log": set()
        }

def save_state(state, port):
    state_file = get_state_file(port)
    with open(state_file, "wb") as f:
        pickle.dump(state, f)