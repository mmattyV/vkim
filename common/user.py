from queue import Queue

class User:
    def __init__(self, username, password=None):
        self.username = username
        self.password = password  # Store the hashed password here.
        # Queue for messages not yet delivered (i.e. unread)
        self.undelivered_messages = Queue()
        # List for messages that have been delivered (read)
        self.read_messages = []

    def queue_message(self, msg):
        """Queue a message for later delivery and store it for history."""
        self.undelivered_messages.put(msg)

    def add_read_message(self, msg):
        """Store a message that has been delivered/read."""
        self.read_messages.append(msg)

    def get_current_messages(self, count):
        """
        Retrieve up to 'count' messages from the undelivered queue.
        As messages are delivered, move them into read_messages.
        Returns a list of messages that have been delivered.
        """
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
        Deletes messages from the user's read messages.
        If delete_info is "ALL" (case-insensitive), clear the entire list.
        Otherwise, if delete_info is a numeric string, delete that many messages from the beginning.
        Returns the number of messages deleted.
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