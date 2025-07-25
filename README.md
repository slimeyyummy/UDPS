# UDPS Protocol (UDP-based Reliable Protocol)  
![Language](https://img.shields.io/badge/C%2B%2B-17-blue.svg)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Platform](https://img.shields.io/badge/Platform-Cross--Platform-lightgrey)  

> A lightweight, reliable, congestion-aware protocol built on top of raw UDP — inspired by QUIC, TCP, and BBR.

---

## ✅ What this project does

The **UDPS Protocol** is a modern take on reliable transport over UDP. Designed for learning, testing, and potentially extending into secure communications, it demonstrates core features of a full transport stack, including:

- 🔐 3-Way Handshake with conceptual key exchange  
- 📦 Reliable, in-order data transfer  
- 📥 Packet reordering buffer  
- 🔁 Retransmission & timeout handling  
- 📶 BBR-inspired congestion control  
- 🧪 XOR-based placeholder encryption (AES/TLS planned)  
- 🧭 Modular client-server architecture  

---

## ✅ How to build

### ✅ Prerequisites
- A C++17-compatible compiler: **GCC**, **Clang**, or **MSVC**
- POSIX or Windows environment (cross-platform)
- `make` (Unix-like) or Visual Studio (Windows)

---

### 🐧 Linux/macOS
```bash
g++ udps.cpp -o udps -std=c++17 -pthread

Building on Windows (using MinGW g++)
Ensure MinGW is installed and its bin directory is in your system's PATH.

Open Git Bash or Command Prompt.

Navigate to the project directory.

Compile the source code:

g++ udps.cpp -o udps.exe -std=c++17 -lws2_32 -lwsock32 -pthread



-lws2_32 -lwsock32: Links against the Windows Sockets libraries (ws2_32.lib and wsock32.lib), which are required for network programming on Windows.

-pthread: Links against the pthreads-win32 library if using a MinGW distribution that includes it. Some MinGW versions might not strictly require -pthread for std::thread, but it's good practice.

Building on Windows (using MSVC - Visual Studio)
Open Visual Studio.

Create a new "Empty Project" (C++).

Add udps.cpp to the project's Source Files.

Configure Project Properties:

Go to Project > Properties.

C/C++ > Language > C++ Language Standard: Set to ISO C++17 Standard (/std:c++17).

Linker > Input > Additional Dependencies: Add Ws2_32.lib.

Build the project.

✅ Example usage
After building, you will have an executable named udps (or udps.exe on Windows).

1. Start the Server
Open a terminal/command prompt and run:

./udps server <listen_port> [encryption_key]



<listen_port>: The port number the server will listen on (e.g., 8080).

[encryption_key]: (Optional) A string to enable conceptual encryption. If provided, both client and server must use the same key.

Example:

./udps server 8080 mysecretkey



You should see output similar to:

Server: Listening on port 8080 (0.0.0.0:8080)
Server: Running. Waiting for clients. Type 'quit' to exit. Type 'send <conn_id> <message>' to echo.



2. Start the Client
Open another terminal/command prompt and run:

./udps client <server_ip> <server_port> [encryption_key]



<server_ip>: The IP address of the server (e.g., 127.0.0.1 for localhost).

<server_port>: The port number the server is listening on (e.g., 8080).

[encryption_key]: (Optional) The same string as used for the server to enable conceptual encryption.

Example:

./udps client 127.0.0.1 8080 mysecretkey



You should see output similar to:

Client: Attempting to connect to 127.0.0.1:8080
Client: Sending SYN (Seq: 1) - Attempt 1
Client: Received SYN-ACK (ConnID: 1, Seq: 123, Ack: 2)
Client: Derived shared encryption key (conceptual).
Client: Sending Handshake Finished ACK (ConnID: 1, Seq: 2, Ack: 124)
Client: Connection established (Handshake Step 3 complete) with ConnID: 1
Client: Type messages to send. Type 'quit' to exit.



3. Send Messages
From Client: Type a message in the client terminal and press Enter.

You: Hello server!



The client will send this message to the server.

From Server (Echo): The server can receive messages and, if desired, send a message back to a specific client using the send command.

Server: send 1 Hello client, I received your message!



(Replace 1 with the actual ConnID shown in the server logs when the client connected).

✅ Protocol overview
The UDPS Protocol implements several key features to provide reliability and congestion control over UDP:

Packet Structure (UDPSPacket)
#pragma pack(push, 1)
struct UDPSPacket {
    uint8_t flag;       // Type of packet (SYN, ACK, DATA, FIN, PING, HEARTBEAT, REKEY)
    uint16_t conn_id;   // Connection/session ID
    uint32_t seq;       // Sequence number for the sender's stream
    uint32_t ack;       // Acknowledgment number for the receiver's stream (cumulative ACK)
    uint16_t length;    // Length of the payload data
    char data[PAYLOAD_BUFFER_SIZE]; // Payload buffer (512 bytes)
};
#pragma pack(pop)



Flag Meanings
SYN (0x01): Synchronization. Used by the client to initiate a new connection (ClientHello).

ACK (0x02): Acknowledgment. Used to confirm receipt of packets and carry acknowledgment numbers. Also used in SYN-ACK and FIN-ACK.

DATA (0x03): Carries application-layer data.

FIN (0x04): Finish. Used to gracefully terminate a connection.

PING (0x05): Used for liveness checks and RTT measurement.

HEARTBEAT (0x06): (Conceptual) For maintaining connection liveness over longer periods.

REKEY (0x07): (Conceptual) For re-establishing encryption keys periodically.

Handshake (3-Way)
Client -> Server: SYN (ClientHello): Client sends a SYN packet with its initial sequence number and a conceptual "public key" in the payload.

Server -> Client: SYN-ACK (ServerHello): Server responds with a SYN-ACK packet acknowledging the client's SYN, assigns a conn_id, includes its own initial sequence number, and a conceptual "public key" in the payload.

Client -> Server: ACK (Handshake Finished ACK): Client sends an ACK packet acknowledging the server's SYN-ACK. The payload contains a special HANDSHAKE_FINISHED_MSG to signal completion of its handshake part. At this point, both client and server derive a shared encryption key, and the connection is fully established.

Encryption (xor_encrypt_decrypt)
A basic XOR cipher is used for conceptual encryption. If an encryption_key is provided during client/server initialization, data payloads are XORed with this key before sending and after receiving. This is a demonstration of where encryption would fit into the protocol and is not cryptographically secure for real-world use. In a production system, this would be replaced by robust ciphers like AES, derived from a strong key exchange (e.g., TLS 1.3 over DTLS).

Retransmission Strategy (Timeout-based)
Both the client and server maintain a map of "unacknowledged packets." If a packet is sent and its acknowledgment is not received within UDPS_TIMEOUT_MS (60ms), it is marked for retransmission. This is a simple timeout-based retransmission.

Packet Reordering
Both client and server implement a reorder_buffer (a std::map<uint32_t, UDPSPacket>) to handle out-of-order packet arrival. If a packet arrives with a sequence number greater than the next_expected_seq, it is buffered. When the next_expected_seq packet arrives, it (and any subsequently buffered in-order packets) are delivered to the application.

BBR-like Congestion Control
A simplified BBR (Bottleneck Bandwidth and RTT) inspired algorithm is implemented to dynamically adjust the sending rate and inflight data.

min_rtt_us: Tracks the minimum Round-Trip Time observed, representing the propagation delay.

delivery_rate_bytes_per_ms: Estimates the bottleneck bandwidth by tracking acknowledged bytes over time.

bytes_in_flight: The amount of data sent but not yet acknowledged.

pacing_rate_bytes_per_ms: The rate at which new packets are released into the network.

bbr_state: Transitions through STARTUP, DRAIN, PROBE_BW, and PROBE_RTT phases.

STARTUP: Aggressively increases pacing_rate to find available bandwidth.

DRAIN: Reduces pacing_rate to drain any queue built up during STARTUP.

PROBE_BW: Cycles through gain factors to maintain high throughput and periodically probe for more bandwidth.

PROBE_RTT: Periodically reduces bytes_in_flight to a minimal level to measure the true min_rtt without queuing delay.

The pacing_rate_bytes_per_ms and target_inflight (congestion window) are adjusted based on these estimates and the current BBR state to optimize for both throughput and low latency. A minimum inflight window is maintained to ensure initial packets can always be sent, allowing the BBR algorithm to bootstrap.

✅ License
This project is licensed under the MIT License.

MIT License

Copyright (c) [Year] [Your Name/Organization Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

