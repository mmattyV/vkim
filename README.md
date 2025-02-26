# Chat Client-Server Project Using Custom/JSON Serialization

This project implements a multi-threaded chat server and a Tkinter-based chat client. Two serialization methods are provided—a custom binary protocol and a JSON-based protocol—for transmitting messages between the client and server.

## Prerequisites
* Python 3.7 or later
* virtualenv (optional, but recommended)

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mmattyV/vkim.git
cd vkim/sockets
```

### 2. Create and Activate the Virtual Environment
If you haven't already created the virtual environment, run:

```bash
python -m venv venv
```

Then activate it:
* On Windows:

```bash
venv\Scripts\activate
```

* On macOS/Linux:

```bash
source venv/bin/activate
```

### 3. Install Dependencies
Make sure you have a valid requirements.txt file in the vkim folder, then run:

```bash
pip install -r requirements.txt
```

## Running the Server

1. Open a terminal and activate your virtual environment if not already activated.
2. Navigate to the server folder:

```bash
cd server
```

3. Run the server:

```bash
python server.py
```

The server will start and listen on the configured host and port (default values are set in config.py). You can override these using command-line arguments (e.g., --host and --port).
Example:

```bash
python server.py --host 127.0.0.1 --port 5050
```

## Running the Client

1. Open another terminal and activate your virtual environment if not already activated.
2. Navigate to the client folder:

```bash
cd client
```

3. Run the client GUI:

```bash
python gui.py
```

You can also specify command-line options for the server host, port, and serialization method.
Example:

```bash
python gui.py --host 127.0.0.1 --port 5050 --serialize json
```

## Testing & Performance Comparison

A separate script (e.g., compare_serialization.py) is provided to compare message sizes between the custom binary protocol and the JSON protocol. To run this script:
1. Ensure the virtual environment is activated.
2. From the main vkim folder, run:

```bash
cd comparison
python compare_serialization.py
```

The script will print the byte sizes for several test messages to help evaluate efficiency and scalability.

## Additional Information

### Configuration
The project configuration (e.g., server host, port, serialization type) is defined in config.py. You can modify this file to change default settings.

### Dependencies
See requirements.txt for a list of all required Python packages.

### Notes
* Ensure that the virtual environment (venv) is active when running the server or client.
* Use the provided command-line options to override default configuration parameters as needed.

# gRPC Chat Application

This is a reimplementation of a chat application using gRPC instead of a custom wire protocol.

## Features

- User account management (create, login, logout, delete)
- Message sending and receiving
- Real-time message delivery using streaming RPCs
- Message history management
- User account listing

## Requirements

- Python 3.6 or higher
- grpcio >= 1.70.0
- grpcio-tools >= 1.70.0
- protobuf >= 5.20.0

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mmattyV/vkim.git
cd vkim/grpc
```

### 2. Create and Activate the Virtual Environment
If you haven't already created the virtual environment, run:

```bash
python -m venv venv
```

Then activate it:
* On Windows:

```bash
venv\Scripts\activate
```

* On macOS/Linux:

```bash
source venv/bin/activate
```

### 3. Install Dependencies
Make sure you have a valid requirements.txt file in the vkim folder, then run:

```bash
pip install -r requirements.txt
```


## Installation

First, switch into the grpc directory:

```bash
cd grpc
```

Run the setup script to install dependencies and generate code from the proto file:

```bash
python setup.py
```

If you already have the dependencies installed, you can skip the dependency installation:

```bash
python setup.py --skip-deps
```

## Running the Application

### Starting the Server

```bash
python -m server.grpc_server 
```

### Running the Command-line Client

```bash
python -m client.grpc_client 
```

### Running the GUI Client

```bash
python -m client.grpc_gui 
```

## Comparison with Original Implementation

This implementation demonstrates several advantages over the original socket-based version:

1. **Reduced code complexity**: Elimination of custom serialization and socket management
2. **Enhanced capabilities**: Built-in support for streaming
3. **Better architecture**: Clear separation of service definition and implementation
4. **Easier maintenance**: Auto-generated client and server code from the protocol definition

For a detailed analysis, see the [Engineering Notebook]

## Implementation Details

### Protocol Definition

The chat service is defined in `message_service.proto` using Protocol Buffers, which defines:

- Service methods for all operations
- Request and response message formats
- Streaming RPC for real-time message delivery

### Server Implementation

The server implements the service interface defined in the proto file, handling:

- User authentication and account management
- Message routing and delivery
- Concurrent client connections

### Client Implementations

Two client implementations are provided:

1. **Command-line client**: Text-based interface for all chat operations
2. **GUI client**: Tkinter-based graphical interface with real-time message updates

### Generated Files

When you run the setup script, it generates the following files in the grpc directory:
- `message_service_pb2.py`: Contains the Protocol Buffer message classes
- `message_service_pb2_grpc.py`: Contains the gRPC client and server classes

These generated files should not be edited manually.

## License

This project is licensed under the MIT License.
