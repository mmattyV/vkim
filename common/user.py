from queue import Queue

class User:
    def __init__(self, username):
        self.username = username
        # Queue for messages that have not yet been delivered.
        self.undelivered_messages = Queue()
        # List to store all messages received (delivered or undelivered).
        self.all_messages = []

    def queue_message(self, msg):
        """Queue a message for later delivery and store it in all_messages."""
        self.undelivered_messages.put(msg)
        self.all_messages.append(msg)

    def add_message(self, msg):
        """Add a message that was delivered immediately to the all_messages list."""
        self.all_messages.append(msg)

    def get_current_messages(self):
        """Retrieve all undelivered messages and remove them from the queue."""
        messages = []
        while not self.undelivered_messages.empty():
            messages.append(self.undelivered_messages.get())
        return messages

    def delete_messages(self, delete_info):
        """
        Deletes messages from the user's message history.
        If delete_info is "ALL" (case-insensitive), clear the entire message history.
        Otherwise, if delete_info is a numeric string, delete that many messages from the beginning.
        Returns the number of messages deleted.
        """
        if delete_info.upper() == "ALL":
            count = len(self.all_messages)
            self.all_messages.clear()
            # Also clear undelivered messages to keep them in sync.
            while not self.undelivered_messages.empty():
                self.undelivered_messages.get()
            return count
        else:
            try:
                num = int(delete_info)
            except ValueError:
                return 0
            count = min(num, len(self.all_messages))
            # Remove the first 'count' messages.
            self.all_messages = self.all_messages[count:]
            # Also remove from undelivered messages if they are among the first ones.
            for _ in range(count):
                if not self.undelivered_messages.empty():
                    self.undelivered_messages.get()
            return count