# server.py

import socket
import threading

# Configuration Constants
PORT = 5050  # Port to listen on
SERVER_HOST_NAME = socket.gethostname()  # Host name of the machine
SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)  # IPv4 address of the machine
HEADER = 64  # Fixed header length in bytes for message length
FORMAT = "utf-8"  # Encoding/decoding format
DISCONNECT_MESSAGE = "!DISCONNECT"  # Special disconnect message
ADDR = (SERVER_HOST, PORT)

# Create the server socket (IPv4, TCP)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

def handle_client(conn, addr):
    """
    Handles an incoming client connection.
    Receives a fixed-length header indicating the message length,
    then reads the message and echoes it back. Closes the connection
    if the disconnect message is received.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            # Receive message length header
            msg_length = conn.recv(HEADER).decode(FORMAT)
            if msg_length:
                msg_length = int(msg_length)
                # Receive the actual message based on its length
                msg = conn.recv(msg_length).decode(FORMAT)
                if msg == DISCONNECT_MESSAGE:
                    connected = False
                print(f"Received from {addr}: {msg}")
                # Echo the message back to the client
                conn.send(msg.encode(FORMAT))
        except Exception as e:
            print(f"[ERROR] {e}")
            break
    conn.close()
    # print(f"[DISCONNECTED] {addr} disconnected.")

def start_server():
    """
    Starts the server and listens for incoming connections.
    For every new connection, a new thread is created to handle it.
    """
    print(f"[STARTING] Server is starting at {SERVER_HOST} on port {PORT}...")
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER_HOST}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
