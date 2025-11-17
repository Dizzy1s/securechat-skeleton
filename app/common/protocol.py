# app/common/protocol.py
# central message types, small helpers for JSON message composition

MSG_TYPE_HELLO = "hello"
MSG_TYPE_SERVER_HELLO = "server_hello"
MSG_TYPE_DH_CLIENT = "dh_client"
MSG_TYPE_DH_SERVER = "dh_server"
MSG_TYPE_REGISTER = "register"
MSG_TYPE_LOGIN = "login"
MSG_TYPE_ENCRYPTED = "encrypted"   # used for wrapped AES payloads during auth
MSG_TYPE_MSG = "msg"               # chat message
MSG_TYPE_RECEIPT_REQ = "receipt_request"
MSG_TYPE_RECEIPT = "receipt"
MSG_TYPE_OK = "ok"
MSG_TYPE_ERR = "err"
MSG_TYPE_CLOSE = "close"
