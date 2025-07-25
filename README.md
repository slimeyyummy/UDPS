#  UDPS Protocol (UDP-based Reliable Protocol)

![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

> A lightweight, reliable, congestion-aware protocol built on top of raw UDP — inspired by QUIC, TCP, and BBR.

---

##  Project Overview

The **UDPS Protocol** is a modern take on reliable transport over UDP. Designed for learning, testing, and potentially secure communication, it includes:


-  3-Way Handshake
-  Reliable, ordered packet delivery
-  Out-of-order packet buffering
-  Retransmission & timeout (60ms)
-  BBR-inspired congestion control
-  XOR encryption (im kinda sleepy so i added basic encryption im gonna add TLS and AES encryption logic tom.

```
SYN (0x01): Synchronization. Used by the client to initiate a new connection (ClientHello).

ACK (0x02): Acknowledgment. Used to confirm receipt of packets and carry acknowledgment numbers. Also used in SYN-ACK and FIN-ACK.

DATA (0x03): Carries application-layer data.

FIN (0x04): Finish. Used to gracefully terminate a connection.

PING (0x05): Used for liveness checks and RTT measurement.

HEARTBEAT (0x06): For maintaining connection liveness over longer periods.

REKEY (0x07): For re-establishing encryption keys periodically.

FIN-ACK (0X08) : to simulate TCP-like graceful connection termination.
```



---

##  How to Build

###  Prerequisites

- C++17 compatible compiler: GCC, Clang, or MSVC
- Windows or Linux/macOS environment
- `make` (Unix) or Visual Studio (Windows)

---

###  Linux/macOS

```bash
g++ udps.cpp -o udps -std=c++17 -pthread
```

### Windows

```
g++ udps.cpp -o udps.exe -std=c++17 -lws2_32 -lwsock32 -pthread
```
