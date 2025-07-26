# Reliable UDP Networking Library

A C++ library providing a reliable transport layer over UDP, suitable as a backend for game servers or other latency-sensitive applications. It is not a specific application, but a foundation to build one upon.

## Core Features

- **Connection Management**: A handshake process establishes and terminates connections cleanly.
- **Reliability**: Guarantees ordered delivery and prevents packet loss through sequence numbers, acknowledgements, and a retransmission mechanism.
- **Congestion Control**: Implements a basic BBR (Bottleneck Bandwidth and Round-trip propagation time) model to adapt to network conditions.
- **Encryption**: All data is encrypted using a simple, fast XOR cipher with a shared secret.
- **Modular Design**: The library is split into a clear `core` and `headers` structure, making it easy to integrate into other projects.

## Compilation

The project is written in C++17. Compile the example using `g++`:

```bash
g++ -std=c++17 -Iheaders -Wall -o udps_app main.cpp core/common.cpp core/client.cpp core/server.cpp -lpthread
```

This command builds the `main.cpp` example, which demonstrates a simple echo server and client.

## Example Usage: Echo Server

The included `main.cpp` provides a basic echo server and client to demonstrate the library's functionality.

### Start the Server

Run the compiled application in server mode, specifying a port:

```bash
./udps_app server <port>
```
Example:
```bash
./udps_app server 8080
```

The server will start and wait for client connections.

### Connect a Client

In a separate terminal, run the application in client mode, providing the server's IP and port:

```bash
./udps_app client <ip_address> <port>
```
Example:
```bash
./udps_app client 127.0.0.1 8080
```

Once connected, you can type any message and press Enter. The server will receive the message and echo it back to your client terminal. Type `exit` to disconnect.
