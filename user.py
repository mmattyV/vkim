from queue import Queue

class User:
    def __init__(self, username):
        self.username = username
        # A simple queue to store undelivered messages
        self.undelivered_messages = Queue()

    def queue_message(self, msg):
        self.undelivered_messages.put(msg)

    def get_current_messages(self):
        messages = []
        while not self.undelivered_messages.empty():
            messages.append(self.undelivered_messages.get())
        return messages