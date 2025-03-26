# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: message_service.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'message_service.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15message_service.proto\x12\x04\x63hat\"#\n\x0fUsernameRequest\x12\x10\n\x08username\x18\x01 \x01(\t\"3\n\x10UsernameResponse\x12\x0e\n\x06\x65xists\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"A\n\x14\x43reateAccountRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\"9\n\x0cLoginRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x17\n\x0fhashed_password\x18\x02 \x01(\t\"X\n\x0c\x41uthResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x10\n\x08username\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x14\n\x0cunread_count\x18\x04 \x01(\x05\"!\n\rLogoutRequest\x12\x10\n\x08username\x18\x01 \x01(\t\"2\n\x0eStatusResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"8\n\x13ListAccountsRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x0f\n\x07pattern\x18\x02 \x01(\t\"J\n\x14ListAccountsResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x10\n\x08\x61\x63\x63ounts\x18\x02 \x03(\t\x12\x0f\n\x07message\x18\x03 \x01(\t\"H\n\x12SendMessageRequest\x12\x0e\n\x06sender\x18\x01 \x01(\t\x12\x11\n\trecipient\x18\x02 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x03 \x01(\t\"6\n\x13ViewMessagesRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\r\n\x05\x63ount\x18\x02 \x01(\x05\"]\n\x14ViewMessagesResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12#\n\x08messages\x18\x02 \x03(\x0b\x32\x11.chat.MessageData\x12\x0f\n\x07message\x18\x03 \x01(\t\"A\n\x0bMessageData\x12\x0e\n\x06sender\x18\x01 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\t\"E\n\x0fMessageResponse\x12\x0e\n\x06sender\x18\x01 \x01(\t\x12\x0f\n\x07\x63ontent\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\t\">\n\x15\x44\x65leteMessagesRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x13\n\x0b\x64\x65lete_info\x18\x02 \x01(\t\"H\n\x12ReplicationRequest\x12\x11\n\toperation\x18\x01 \x01(\t\x12\x0c\n\x04\x64\x61ta\x18\x02 \x01(\t\x12\x11\n\tupdate_id\x18\x03 \x01(\t\"\x1c\n\x0bPingRequest\x12\r\n\x05\x64ummy\x18\x01 \x01(\t\"2\n\x0cPingResponse\x12\x0f\n\x07message\x18\x01 \x01(\t\x12\x11\n\tsender_id\x18\x02 \x01(\t\"\x0f\n\rLeaderRequest\"(\n\x0eLeaderResponse\x12\x16\n\x0eleader_address\x18\x01 \x01(\t2\xb4\x06\n\x0b\x43hatService\x12>\n\rCheckUsername\x12\x15.chat.UsernameRequest\x1a\x16.chat.UsernameResponse\x12?\n\rCreateAccount\x12\x1a.chat.CreateAccountRequest\x1a\x12.chat.AuthResponse\x12/\n\x05Login\x12\x12.chat.LoginRequest\x1a\x12.chat.AuthResponse\x12\x33\n\x06Logout\x12\x13.chat.LogoutRequest\x1a\x14.chat.StatusResponse\x12<\n\rDeleteAccount\x12\x15.chat.UsernameRequest\x1a\x14.chat.StatusResponse\x12\x45\n\x0cListAccounts\x12\x19.chat.ListAccountsRequest\x1a\x1a.chat.ListAccountsResponse\x12=\n\x0bSendMessage\x12\x18.chat.SendMessageRequest\x1a\x14.chat.StatusResponse\x12\x45\n\x0cViewMessages\x12\x19.chat.ViewMessagesRequest\x1a\x1a.chat.ViewMessagesResponse\x12\x43\n\x0e\x44\x65leteMessages\x12\x1b.chat.DeleteMessagesRequest\x1a\x14.chat.StatusResponse\x12\x41\n\x0fReceiveMessages\x12\x15.chat.UsernameRequest\x1a\x15.chat.MessageResponse0\x01\x12\x44\n\x12ReplicateOperation\x12\x18.chat.ReplicationRequest\x1a\x14.chat.StatusResponse\x12-\n\x04Ping\x12\x11.chat.PingRequest\x1a\x12.chat.PingResponse\x12\x36\n\tGetLeader\x12\x13.chat.LeaderRequest\x1a\x14.chat.LeaderResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'message_service_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_USERNAMEREQUEST']._serialized_start=31
  _globals['_USERNAMEREQUEST']._serialized_end=66
  _globals['_USERNAMERESPONSE']._serialized_start=68
  _globals['_USERNAMERESPONSE']._serialized_end=119
  _globals['_CREATEACCOUNTREQUEST']._serialized_start=121
  _globals['_CREATEACCOUNTREQUEST']._serialized_end=186
  _globals['_LOGINREQUEST']._serialized_start=188
  _globals['_LOGINREQUEST']._serialized_end=245
  _globals['_AUTHRESPONSE']._serialized_start=247
  _globals['_AUTHRESPONSE']._serialized_end=335
  _globals['_LOGOUTREQUEST']._serialized_start=337
  _globals['_LOGOUTREQUEST']._serialized_end=370
  _globals['_STATUSRESPONSE']._serialized_start=372
  _globals['_STATUSRESPONSE']._serialized_end=422
  _globals['_LISTACCOUNTSREQUEST']._serialized_start=424
  _globals['_LISTACCOUNTSREQUEST']._serialized_end=480
  _globals['_LISTACCOUNTSRESPONSE']._serialized_start=482
  _globals['_LISTACCOUNTSRESPONSE']._serialized_end=556
  _globals['_SENDMESSAGEREQUEST']._serialized_start=558
  _globals['_SENDMESSAGEREQUEST']._serialized_end=630
  _globals['_VIEWMESSAGESREQUEST']._serialized_start=632
  _globals['_VIEWMESSAGESREQUEST']._serialized_end=686
  _globals['_VIEWMESSAGESRESPONSE']._serialized_start=688
  _globals['_VIEWMESSAGESRESPONSE']._serialized_end=781
  _globals['_MESSAGEDATA']._serialized_start=783
  _globals['_MESSAGEDATA']._serialized_end=848
  _globals['_MESSAGERESPONSE']._serialized_start=850
  _globals['_MESSAGERESPONSE']._serialized_end=919
  _globals['_DELETEMESSAGESREQUEST']._serialized_start=921
  _globals['_DELETEMESSAGESREQUEST']._serialized_end=983
  _globals['_REPLICATIONREQUEST']._serialized_start=985
  _globals['_REPLICATIONREQUEST']._serialized_end=1057
  _globals['_PINGREQUEST']._serialized_start=1059
  _globals['_PINGREQUEST']._serialized_end=1087
  _globals['_PINGRESPONSE']._serialized_start=1089
  _globals['_PINGRESPONSE']._serialized_end=1139
  _globals['_LEADERREQUEST']._serialized_start=1141
  _globals['_LEADERREQUEST']._serialized_end=1156
  _globals['_LEADERRESPONSE']._serialized_start=1158
  _globals['_LEADERRESPONSE']._serialized_end=1198
  _globals['_CHATSERVICE']._serialized_start=1201
  _globals['_CHATSERVICE']._serialized_end=2021
# @@protoc_insertion_point(module_scope)
