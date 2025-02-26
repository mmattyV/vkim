from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class UsernameRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class UsernameResponse(_message.Message):
    __slots__ = ("exists", "message")
    EXISTS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    exists: bool
    message: str
    def __init__(self, exists: bool = ..., message: _Optional[str] = ...) -> None: ...

class CreateAccountRequest(_message.Message):
    __slots__ = ("username", "hashed_password")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    HASHED_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    username: str
    hashed_password: str
    def __init__(self, username: _Optional[str] = ..., hashed_password: _Optional[str] = ...) -> None: ...

class LoginRequest(_message.Message):
    __slots__ = ("username", "hashed_password")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    HASHED_PASSWORD_FIELD_NUMBER: _ClassVar[int]
    username: str
    hashed_password: str
    def __init__(self, username: _Optional[str] = ..., hashed_password: _Optional[str] = ...) -> None: ...

class AuthResponse(_message.Message):
    __slots__ = ("success", "username", "message", "unread_count")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    UNREAD_COUNT_FIELD_NUMBER: _ClassVar[int]
    success: bool
    username: str
    message: str
    unread_count: int
    def __init__(self, success: bool = ..., username: _Optional[str] = ..., message: _Optional[str] = ..., unread_count: _Optional[int] = ...) -> None: ...

class LogoutRequest(_message.Message):
    __slots__ = ("username",)
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    username: str
    def __init__(self, username: _Optional[str] = ...) -> None: ...

class StatusResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...

class ListAccountsRequest(_message.Message):
    __slots__ = ("username", "pattern")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    username: str
    pattern: str
    def __init__(self, username: _Optional[str] = ..., pattern: _Optional[str] = ...) -> None: ...

class ListAccountsResponse(_message.Message):
    __slots__ = ("success", "accounts", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    ACCOUNTS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    accounts: _containers.RepeatedScalarFieldContainer[str]
    message: str
    def __init__(self, success: bool = ..., accounts: _Optional[_Iterable[str]] = ..., message: _Optional[str] = ...) -> None: ...

class SendMessageRequest(_message.Message):
    __slots__ = ("sender", "recipient", "content")
    SENDER_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    sender: str
    recipient: str
    content: str
    def __init__(self, sender: _Optional[str] = ..., recipient: _Optional[str] = ..., content: _Optional[str] = ...) -> None: ...

class ViewMessagesRequest(_message.Message):
    __slots__ = ("username", "count")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    username: str
    count: int
    def __init__(self, username: _Optional[str] = ..., count: _Optional[int] = ...) -> None: ...

class ViewMessagesResponse(_message.Message):
    __slots__ = ("success", "messages", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    messages: _containers.RepeatedCompositeFieldContainer[MessageData]
    message: str
    def __init__(self, success: bool = ..., messages: _Optional[_Iterable[_Union[MessageData, _Mapping]]] = ..., message: _Optional[str] = ...) -> None: ...

class MessageData(_message.Message):
    __slots__ = ("sender", "content", "timestamp")
    SENDER_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    sender: str
    content: str
    timestamp: str
    def __init__(self, sender: _Optional[str] = ..., content: _Optional[str] = ..., timestamp: _Optional[str] = ...) -> None: ...

class MessageResponse(_message.Message):
    __slots__ = ("sender", "content", "timestamp")
    SENDER_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    sender: str
    content: str
    timestamp: str
    def __init__(self, sender: _Optional[str] = ..., content: _Optional[str] = ..., timestamp: _Optional[str] = ...) -> None: ...

class DeleteMessagesRequest(_message.Message):
    __slots__ = ("username", "delete_info")
    USERNAME_FIELD_NUMBER: _ClassVar[int]
    DELETE_INFO_FIELD_NUMBER: _ClassVar[int]
    username: str
    delete_info: str
    def __init__(self, username: _Optional[str] = ..., delete_info: _Optional[str] = ...) -> None: ...
