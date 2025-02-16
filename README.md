# Chat Client-Server Project

This project implements a multi-threaded chat server and a Tkinter-based chat client. Two serialization methods are provided—a custom binary protocol and a JSON-based protocol—for transmitting messages between the client and server.

## Prerequisites
* Python 3.7 or later
* virtualenv (optional, but recommended)

## Setup

### 1. Clone the Repository
git clone https://github.com/mmattyV/vkim.git
cd vkim

### 2. Create and Activate the Virtual Environment
If you haven't already created the virtual environment, run:

python -m venv venv

Then activate it:
* On Windows:

venv\Scripts\activate

* On macOS/Linux:

source venv/bin/activate

### 3. Install Dependencies
Make sure you have a valid requirements.txt file in the vkim folder, then run:

pip install -r requirements.txt

## Running the Server

1. Open a terminal and activate your virtual environment if not already activated.
2. Navigate to the server folder:

cd server

3. Run the server:

python server.py

The server will start and listen on the configured host and port (default values are set in config.py). You can override these using command-line arguments (e.g., --host and --port).
Example:

python server.py --host 127.0.0.1 --port 5050

## Running the Client

1. Open another terminal and activate your virtual environment if not already activated.
2. Navigate to the client folder:

cd client

3. Run the client GUI:

python gui.py

You can also specify command-line options for the server host, port, and serialization method.
Example:

python gui.py --host 127.0.0.1 --port 5050 --serialize json

## Testing & Performance Comparison

A separate script (e.g., compare_serialization.py) is provided to compare message sizes between the custom binary protocol and the JSON protocol. To run this script:
1. Ensure the virtual environment is activated.
2. From the main vkim folder, run:

python compare_serialization.py

The script will print the byte sizes for several test messages to help evaluate efficiency and scalability.

## Additional Information

### Configuration
The project configuration (e.g., server host, port, serialization type) is defined in config.py. You can modify this file to change default settings.

### Dependencies
See requirements.txt for a list of all required Python packages.

### Notes
* Ensure that the virtual environment (venv) is active when running the server or client.
* Use the provided command-line options to override default configuration parameters as needed.

## License

This project is licensed under the [Your License Name] License.

Feel free to customize this README with additional details as needed for your project.