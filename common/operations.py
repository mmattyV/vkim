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
    CHECK_USERNAME = 10
    LOGIN = 11
    CREATE_ACCOUNT = 12
    DELETE_ACCOUNT = 13
    LIST_ACCOUNTS = 14
    SEND_MESSAGE = 15
    VIEW_UNDELIVERED_MESSAGES = 16
    LOGOUT = 17

    # Additional operation, if needed
    RECEIVE_CURRENT_MESSAGE = 20
