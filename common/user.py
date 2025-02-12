from queue import Queue

class User:
    """
    Represents a user in the chat system with message management capabilities.

    This class handles both undelivered (queued) and delivered (read) messages for a user,
    providing methods for message queuing, delivery, and management.

    Attributes:
        username (str): The user's unique identifier
        password (str, optional): The user's hashed password
        undelivered_messages (Queue): Queue containing messages not yet delivered to the user
        read_messages (list): List of messages that have been delivered and read

    Example:
        >>> user = User("john_doe", "hashed_password123")
        >>> user.queue_message("Hello from Alice!")
        >>> messages = user.get_current_messages(1)
        >>> print(messages)
        ['Hello from Alice!']
    """
    def __init__(self, username, password=None):
        """
        Initialize a new User instance.

        Args:
            username (str): The username for the new user
            password (str, optional): The user's hashed password. Defaults to None.
        """
        self.username = username
        self.password = password 
        # Queue for messages not yet delivered (i.e. unread)
        self.undelivered_messages = Queue()
        # List for messages that have been delivered (read)
        self.read_messages = []

    def queue_message(self, msg):
        """
        Queue a message for later delivery.

        Adds a message to the undelivered messages queue. Messages in this queue
        will be delivered when the user requests to view their messages.

        Args:
            msg (str): The message to queue for later delivery
        """
        self.undelivered_messages.put(msg)

    def add_read_message(self, msg):
        """
        Mark a message as read and store it in history.

        Adds a message to the read messages list, typically called after
        a message has been successfully delivered to the user.

        Args:
            msg (str): The message to mark as read
        """
        self.read_messages.append(msg)

    def get_current_messages(self, count):
        """
        Retrieve and mark as read up to 'count' undelivered messages.

        Retrieves messages from the undelivered queue, marks them as read,
        and returns them to the caller. This method modifies both the
        undelivered_messages queue and read_messages list.

        Args:
            count (int): Maximum number of messages to retrieve

        Returns:
            list: List of retrieved messages, may be fewer than 'count' if
                  there aren't enough undelivered messages

        Example:
            >>> user.queue_message("Message 1")
            >>> user.queue_message("Message 2")
            >>> messages = user.get_current_messages(1)
            >>> print(messages)
            ['Message 1']
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
        Delete messages from the user's read message history.

        Args:
            delete_info (str): Either "ALL" to delete all messages, or a number
                             indicating how many messages to delete from the beginning

        Returns:
            int: Number of messages actually deleted

        Raises:
            ValueError: If delete_info is neither "ALL" nor a valid number string

        Example:
            >>> user.add_read_message("Message 1")
            >>> user.add_read_message("Message 2")
            >>> deleted = user.delete_read_messages("ALL")
            >>> print(deleted)
            2
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