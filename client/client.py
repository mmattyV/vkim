import socket

# Configuration must match the server's settings
FORMAT = "utf-8"
HEADER = 64
PORT = 5050

# Determine the server's IP based on the local machine's hostname
SERVER_HOST_NAME = socket.gethostname()
SERVER_HOST = socket.gethostbyname(SERVER_HOST_NAME)
ADDR = (SERVER_HOST, PORT)

def send(msg):
    """
    Connects to the server, sends a message with a fixed-width header,
    receives the echo from the server, and prints it.
    """
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(ADDR)
    
    # Encode the message and compute its length
    message = msg.encode(FORMAT)
    msg_length = len(message)
    send_length = str(msg_length).encode(FORMAT)
    send_length += b' ' * (HEADER - len(send_length))
    
    # Send the header and then the message
    client.send(send_length)
    client.send(message)
    
    # Receive and print the response
    response = client.recv(2048).decode(FORMAT)
    print(f"Received: {response}")
    client.close()

if __name__ == "__main__":
    send("Hello, Server!")
    # # Optionally, you can also test disconnecting:
    # send("!DISCONNECT")