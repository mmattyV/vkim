# config.py
import socket

class ServerConfig:
    """Server configuration settings"""
    PORT = 5050
    SERVER_HOST_NAME = socket.gethostname()
    SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)
    HEADER = 8
    FORMAT = "utf-8"
    DISCONNECT_MESSAGE = "!DISCONNECT"
    SERIALIZE = "custom"
    
    @property
    def ADDR(self):
        """Server address tuple"""
        return (self.SERVER_HOST, self.PORT)

# Create a singleton instance
config = ServerConfig()