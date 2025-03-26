# common/user.py
from queue import Queue

class User:
    """
    Represents a user in the chat system with message management capabilities.
    """
    def __init__(self, username, password=None):
        self.username = username
        self.password = password 
        # Queue for messages not yet delivered (i.e., unread)
        self.undelivered_messages = Queue()
        # List for messages that have been delivered (read)
        self.read_messages = []

    def queue_message(self, msg):
        """Queue a message for later delivery."""
        self.undelivered_messages.put(msg)

    def add_read_message(self, msg):
        """Add a message to the read messages history."""
        self.read_messages.append(msg)

    def get_current_messages(self, count):
        """Retrieve up to 'count' messages from the undelivered queue."""
        messages = []
        for _ in range(count):
            if self.undelivered_messages.empty():
                break
            msg = self.undelivered_messages.get()
            messages.append(msg)
            self.add_read_message(msg)
        return messages

    def delete_read_messages(self, delete_info):
        """
        Delete messages from the read messages list.
        delete_info is either "ALL" or a number (as a string) indicating how many messages to delete.
        """
        if delete_info.upper() == "ALL":
            count = len(self.read_messages)
            self.read_messages.clear()
            return count
        else:
            try:
                num = int(delete_info)
            except ValueError:
                return 0
            count = min(num, len(self.read_messages))
            self.read_messages = self.read_messages[count:]
            return count

    def __getstate__(self):
        """
        Return a picklable state by converting the undelivered_messages queue to a list.
        """
        state = self.__dict__.copy()
        # Convert the queue to a list of messages (the Queue object itself is not pickleable)
        state['undelivered_messages'] = list(self.undelivered_messages.queue)
        return state

    def __setstate__(self, state):
        """
        Restore state and reinitialize the undelivered_messages as a Queue.
        """
        from queue import Queue
        undelivered = state.pop('undelivered_messages', [])
        self.__dict__.update(state)
        self.undelivered_messages = Queue()
        for msg in undelivered:
            self.undelivered_messages.put(msg)