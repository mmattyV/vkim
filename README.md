# Chat Client-Server Project

This project implements a multi-threaded chat server and a Tkinter-based chat client, supporting two serialization methods: a custom binary protocol and a JSON-based protocol.

## Features

- Multi-threaded server for handling multiple clients
- Custom and JSON serialization for message transmission
- Tkinter GUI for client interaction
- Performance comparison between serialization methods

## Prerequisites

- Python 3.7 or later
- `virtualenv` (optional but recommended)

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mmattyV/vkim.git
cd vkim
```

### 2. Create and Activate the Virtual Environment

#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

#### On macOS/Linux:
```bash
python -m venv venv
source venv/bin/activate
```

---

## Running the Server

1. Open a terminal and activate the virtual environment.
2. Navigate to the server directory:
   ```bash
   cd sockets/server
   ```
3. Run the server:
   ```bash
   python server.py
   ```
   The server will listen on default values set in `config.py`. You can override them:
   ```bash
   python server.py --host 127.0.0.1 --port 5050
   ```

## Running the Client

1. Open another terminal and activate the virtual environment.
2. Navigate to the client directory:
   ```bash
   cd sockets/client
   ```
3. Run the client GUI:
   ```bash
   python gui.py
   ```
   Optionally, specify parameters:
   ```bash
   python gui.py --host 127.0.0.1 --port 5050 --serialize json
   ```

---

## Testing & Performance Comparison

To compare the efficiency of the custom binary protocol vs. JSON serialization:

```bash
cd sockets/comparison
python compare_serialization.py
```

The script will display byte sizes of test messages to evaluate efficiency.

---

## Configuration

Project settings (server host, port, serialization type) are defined in `config.py`. Modify this file to adjust default values.

## Notes

- Ensure the virtual environment is activated when running the server or client.
- Use command-line options to override default configurations.

---

# gRPC Chat Application

This is a reimplementation of the chat application using gRPC instead of a custom socket-based protocol.

## Features

- User account management (create, login, logout, delete)
- Message sending and real-time delivery using streaming RPCs
- Message history management
- User account listing

## Prerequisites

- Python 3.6 or higher
- `grpcio >= 1.70.0`
- `grpcio-tools >= 1.70.0`
- `protobuf >= 5.20.0`

---

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/mmattyV/vkim.git
cd vkim
```

### 2. Create and Activate the Virtual Environment

#### On Windows:
```bash
python -m venv venv
venv\Scripts\activate
```

#### On macOS/Linux:
```bash
python -m venv venv
source venv/bin/activate
```

---

## Installation

Navigate to the `grpc` directory:

```bash
cd grpc
```

Run the setup script to install dependencies and generate code from the `.proto` file:

```bash
python setup.py
```

To skip dependency installation:

```bash
python setup.py --skip-deps
```

---

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

---

## Comparison with Original Implementation

This gRPC-based version improves upon the socket-based implementation by:

1. **Reducing code complexity**: Eliminates custom serialization and socket management.
2. **Enhancing capabilities**: Supports streaming natively.
3. **Improving architecture**: Clear separation between service definition and implementation.
4. **Easing maintenance**: Auto-generates client and server code from the `.proto` file.

For a detailed analysis, refer to the [Engineering Notebook].

---

## Implementation Details

### Protocol Definition

The chat service is defined in `message_service.proto` using Protocol Buffers, specifying:

- Service methods for chat operations
- Request and response message formats
- Streaming RPC for real-time messaging

### Server Implementation

The gRPC server handles:

- User authentication and account management
- Message routing and delivery
- Concurrent client connections

### Client Implementations

Two client versions are available:

1. **Command-line client**: Text-based interface.
2. **GUI client**: Tkinter-based interface with real-time updates.

### Generated Files

Running the setup script generates:

- `message_service_pb2.py`: Protocol Buffer message classes
- `message_service_pb2_grpc.py`: gRPC client and server classes

These files should not be modified manually.

---

## License

This project is licensed under the MIT License.

