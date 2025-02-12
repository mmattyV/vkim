from enum import IntEnum

class Operations(IntEnum):
    # SERVER SIDE OPERATIONS (sent to client)
    SUCCESS = 0
    FAILURE = 1
    ACCOUNT_ALREADY_EXISTS = 2
    ACCOUNT_DOES_NOT_EXIST = 3
    LIST_OF_ACCOUNTS = 4
    LIST_OF_MESSAGES = 5

    # CLIENT SIDE OPERATIONS (sent to server)
    LOGIN = 10
    CREATE_ACCOUNT = 11
    DELETE_ACCOUNT = 12
    LIST_ACCOUNTS = 13
    SEND_MESSAGE = 14
    VIEW_UNDELIVERED_MESSAGES = 15
    LOGOUT = 16

    # Additional operation, if needed
    RECEIVE_CURRENT_MESSAGE = 20
