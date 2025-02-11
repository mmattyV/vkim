# Phase 1: Wire Protocol & Data Structures

## Design Your Message Formats

### Custom Protocol
- **Define message types** (e.g., `CREATE_ACCOUNT`, `LOGIN`, `SEND_MESSAGE`, `READ_MESSAGES`, etc.).
- **Decide on headers** (message type, payload length) and field ordering.
- **Document the byte layout.**

### JSON Protocol
- **Define JSON object structures** with keys like `"action"`, `"data"`, etc.

## Develop Serialization/Deserialization Routines
- Create a library/module for converting Python objects into both the custom binary format and JSON strings.
- Implement tests to verify correctness.

---

# Phase 2: Server Implementation

## Basic Server Setup
- Create a TCP server that listens on a configurable port.
- Handle multiple clients (using threads or asyncio).

## Implement Business Logic

### Account Management
- Store accounts (using dictionaries or a simple database file).
- Implement password checks and secure transmission.

### Message Routing & Storage
- When a message is sent, check recipient availability; store if offline.
- Allow querying for unread messages and message deletion.

## Protocol Handling
- Write routines to parse incoming data for both protocol variants.
- Design your server to be protocol-agnostic where possible (e.g., a core service layer that works on parsed command objects).

---

# Phase 3: Client Implementation (with GUI)

## Develop a Tkinter-Based GUI

### Login/Account Creation Screen
- Form for entering a username and password.
- Logic to switch between “create account” and “login” based on server response.

### Main Chat Window
- Text area for displaying messages.
- Input fields/buttons for sending messages.
- Account listing with support for wildcards and pagination if needed.

## Networking Integration
- Use a background thread or asynchronous calls to communicate with the server.
- Ensure the GUI remains responsive while waiting for network operations.

## Configuration
- Allow the user to specify server connection details via a configuration file or command-line parameters.

---

# Phase 4: Testing & Performance Evaluation

## Unit & Integration Tests
- Write tests for the serialization/deserialization routines.
- Test server logic (account creation, login, message storage) using simulated client connections.
- Test the client GUI for basic usability (manual testing might be key here).

## Performance Comparison
- Measure the size and efficiency of messages using your custom protocol versus JSON.
- Log and document these findings in your engineering notebook.
- Reflect on how these differences might affect scalability and efficiency.

---

# Phase 5: Documentation & Code Review Preparation

## Engineering Notebook
- Document design decisions, protocol formats, testing strategies, and performance comparisons.

## Code Documentation
- Comment code thoroughly, explaining design choices.
- Write a README detailing how to run the server and client, configuration options, and protocol details.

## Test Coverage
- Ensure that unit tests cover critical functionality.

## Prepare for Code Reviews
- Organize your code repository and documentation.
- Prepare to both give and receive constructive feedback.
