#include <iostream>
#include <string>
#include <vector>
#include <cstring>      // For memcpy, memset
#include <cstdint>      // For uint8_t, uint16_t, uint32_t
#include <cstdio>       // For perror
#include <cstdlib>      // For exit, rand, srand
#include <ctime>        // For time
#include <map>          // For server to manage connections
#include <chrono>       // For timeouts
#include <thread>       // For std::this_thread::sleep_for
#include <mutex>        // For std::mutex
#include <atomic>       // For atomic boolean to control loops
#include <queue>        // For send/receive buffers
#include <condition_variable> // For signaling between threads
#include <algorithm>    // For std::max
#include <utility>      // For std::piecewise_construct, std::forward_as_tuple
#include <set>          // For managing active connection IDs
#include <functional>   // For std::hash
#include <sstream>      // For stringstream
#include <iomanip>      // For std::hex, std::setw, std::setfill

// Platform-specific headers for sockets
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h> // For getaddrinfo, inet_pton, inet_ntop
    #pragma comment(lib, "ws2_32.lib")
    #define UDPS_SOCKET SOCKET
    #define UDPS_INVALID_SOCKET INVALID_SOCKET
    #define UDPS_SOCKET_ERROR SOCKET_ERROR
    #define UDPS_CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>     // For close
    #include <netdb.h>      // For getaddrinfo
    #include <errno.h>      // For errno and strerror
    #define UDPS_SOCKET int
    #define UDPS_INVALID_SOCKET -1
    #define UDPS_SOCKET_ERROR -1
    #define UDPS_CLOSE_SOCKET close
#endif

// --- ANSI Escape Codes for Colored Output ---
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

// --- Global Logger Function ---
std::mutex log_mutex;
void log_message(const std::string& prefix, const std::string& message, const std::string& color = RESET) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << color << prefix << message << RESET << std::endl;
}

// --- UDPS Protocol Constants ---
const int MAX_PACKET_SIZE = 512 + sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(uint32_t) + sizeof(uint16_t);
const int PAYLOAD_BUFFER_SIZE = 512;
const int UDPS_TIMEOUT_MS = 200; // Timeout for ACK/response in milliseconds
const int UDPS_MAX_RETRIES = 5;  // Max retransmission attempts
const int UDPS_INITIAL_CWND = 1; // Initial congestion window size (used as a base for BBR inflight)
const int UDPS_MAX_CWND = 10;    // Max congestion window size for this demo (used as a base for BBR inflight)

// --- UDPSPacket Structure ---
// Using #pragma pack to ensure no padding for binary serialization
#pragma pack(push, 1) // Push current packing alignment and set to 1-byte alignment
struct UDPSPacket {
    uint8_t flag;       // 0x01=SYN, 0x02=ACK, 0x03=DATA, 0x04=FIN, 0x05=PING, 0x06=HEARTBEAT, 0x07=REKEY
    uint16_t conn_id;   // connection/session ID
    uint32_t seq;       // sequence number
    uint32_t ack;       // ack number
    uint16_t length;    // length of payload
    char data[PAYLOAD_BUFFER_SIZE]; // payload buffer

    // Constructor to initialize members
    UDPSPacket() : flag(0), conn_id(0), seq(0), ack(0), length(0) {
        memset(data, 0, PAYLOAD_BUFFER_SIZE);
    }
};
#pragma pack(pop) // Pop the packing alignment back to its previous value

// --- UDPSPacket Flags ---
enum UDPSFlag : uint8_t {
    SYN       = 0x01,
    ACK       = 0x02,
    DATA      = 0x03,
    FIN       = 0x04,
    PING      = 0x05,
    HEARTBEAT = 0x06,
    REKEY     = 0x07,
    FIN_ACK   = 0x08   // ✅ Add this
};


// --- Special Handshake Payload ---
const std::string HANDSHAKE_FINISHED_MSG = "UDPS_HANDSHAKE_FINISHED";

// --- Packet Serialization/Deserialization ---
// Converts UDPSPacket struct to a char array for sending over UDP
std::vector<char> serialize_packet(const UDPSPacket& packet) {
    std::vector<char> buffer(sizeof(UDPSPacket));
    memcpy(buffer.data(), &packet, sizeof(UDPSPacket));
    return buffer;
}

// Converts a char array received over UDP back to UDPSPacket struct
UDPSPacket deserialize_packet(const char* buffer) {
    UDPSPacket packet;
    memcpy(&packet, buffer, sizeof(UDPSPacket));
    return packet;
}

// --- Conceptual Key Exchange (like QUIC's TLS 1.3 Handshake) ---
// In a real-world scenario, this would involve complex cryptographic primitives
// like Diffie-Hellman key exchange (e.g., ECDH) to derive a shared secret,
// followed by a Key Derivation Function (KDF) to generate symmetric encryption keys.
// This is a simplified, conceptual placeholder.
std::string generate_shared_secret(const std::string& local_private_key, const std::string& remote_public_key) {
    // In a real scenario:
    // 1. Generate ephemeral Diffie-Hellman (DH) or Elliptic Curve Diffie-Hellman (ECDH) key pair.
    // 2. Exchange public keys.
    // 3. Compute shared secret using local private key and remote public key.
    // 4. Use a KDF (e.g., HKDF) to derive separate encryption keys for sending and receiving.

    // For this example, we'll just combine the provided keys in a simple way.
    // This is NOT cryptographically secure and is for demonstration of concept only.
    std::string combined_key = local_private_key + remote_public_key;
    size_t hash_val = std::hash<std::string>{}(combined_key);
    std::stringstream ss;
    ss << std::hex << std::setw(32) << std::setfill('0') << hash_val;
    return ss.str(); // Return a "derived" key (hash for demo)
}

// --- Simple XOR Pseudo-Encryption ---
// This is still used for the actual data encryption, but the 'key'
// would ideally be derived from a secure key exchange.
void xor_encrypt_decrypt(char* data, size_t length, const std::string& key) {
    if (key.empty()) return;
    for (size_t i = 0; i < length; ++i) {
        data[i] = data[i] ^ key[i % key.length()];
    }
}

// --- Utility function to convert sockaddr to string (IPv4/IPv6) ---
std::string sockaddr_to_string(const sockaddr_storage* sa, socklen_t salen) {
    char ip_str[INET6_ADDRSTRLEN];
    std::string port_str;

    if (sa->ss_family == AF_INET) {
        const sockaddr_in* s = reinterpret_cast<const sockaddr_in*>(sa);
        inet_ntop(AF_INET, &s->sin_addr, ip_str, sizeof(ip_str));
        port_str = std::to_string(ntohs(s->sin_port));
    } else if (sa->ss_family == AF_INET6) {
        const sockaddr_in6* s = reinterpret_cast<const sockaddr_in6*>(sa);
        inet_ntop(AF_INET6, &s->sin6_addr, ip_str, sizeof(ip_str));
        port_str = std::to_string(ntohs(s->sin6_port));
    } else {
        return "Unknown Address Family";
    }
    return std::string(ip_str) + ":" + port_str;
}


// --- UDPS Client Class ---
class UDPSClient {
private:
    UDPS_SOCKET client_sock;
    sockaddr_storage server_addr_storage; // Use sockaddr_storage for IPv4/IPv6
    socklen_t server_addr_len;
    uint16_t current_conn_id;
    uint32_t next_seq_num;      // Next sequence number for outgoing data
    uint32_t expected_ack_num;  // Next sequence number expected from server
    std::string encryption_key; // This would be the derived symmetric key in a real system
    std::string client_private_key; // For conceptual key exchange
    std::atomic<bool> connected; // Atomic flag for connection status

    // BBR-inspired Congestion Control variables
    enum BBRState { STARTUP, DRAIN, PROBE_BW, PROBE_RTT };
    BBRState bbr_state;
    long long min_rtt_us; // Minimum RTT observed in microseconds
    double delivery_rate_bytes_per_ms; // Estimated bandwidth in bytes/ms
    std::chrono::steady_clock::time_point last_delivery_rate_update_time;
    size_t bytes_acked_since_last_rate_update;
    size_t bytes_in_flight; // Total bytes sent but not yet ACKed
    double pacing_rate_bytes_per_ms; // Rate at which to send bytes
    double bbr_current_gain; // Current gain factor for pacing and inflight window
    std::vector<double> bbr_gains = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}; // Simplified cycle for ProbeBW
    int bbr_probe_gain_cycle_index;
    std::chrono::steady_clock::time_point last_rtt_probe_time;
    long long rtt_probe_interval_ms; // How often to enter PROBE_RTT state
    long long rtt_probe_duration_ms; // How long to stay in PROBE_RTT state
    long long last_sent_packet_time_us; // For pacing control
    std::chrono::steady_clock::time_point bbr_probe_rtt_start_time; // Added missing member

    std::map<uint32_t, std::pair<UDPSPacket, std::chrono::steady_clock::time_point>> unacked_packets; // Packets sent but not yet ACKed
    std::mutex unacked_mutex; // Mutex for unacked_packets

    // Packet Reordering Buffer
    std::map<uint32_t, UDPSPacket> reorder_buffer;
    std::queue<std::string> received_messages_queue; // For delivering ordered messages to application
    std::mutex receive_mutex; // Mutex for reorder_buffer and received_messages_queue

    // Helper to set socket timeout
    void set_socket_timeout(int ms) {
        #ifdef _WIN32
            DWORD timeout = ms;
            setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        #else
            struct timeval tv;
            tv.tv_sec = ms / 1000;
            tv.tv_usec = (ms % 1000) * 1000;
            setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        #endif
    }

    // Process incoming ACKs for congestion control
    void process_ack(uint32_t ack_num) {
        std::lock_guard<std::mutex> lock(unacked_mutex);
        // Remove packets that are acknowledged. ack_num acknowledges up to ack_num - 1.
        auto it = unacked_packets.begin();
        while (it != unacked_packets.end() && it->first < ack_num) {
            log_message(MAGENTA, "Client: ACKed packet (Seq: " + std::to_string(it->first) + "). Removing from unacked queue.");
            
            // Update RTT and delivery rate estimates
            auto now = std::chrono::steady_clock::now();
            long long current_rtt_us = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second.second).count();
            if (min_rtt_us == 0 || current_rtt_us < min_rtt_us) {
                min_rtt_us = current_rtt_us;
                log_message(MAGENTA, "Client: New Min RTT: " + std::to_string(min_rtt_us) + " us");
            }
            
            bytes_acked_since_last_rate_update += it->second.first.length;
            bytes_in_flight -= it->second.first.length;

            it = unacked_packets.erase(it);
        }
        update_bbr_state(); // Update BBR state after processing ACKs
    }

    // Handle retransmissions
    void handle_retransmissions() {
        std::lock_guard<std::mutex> lock(unacked_mutex);
        auto now = std::chrono::steady_clock::now();
        for (auto it = unacked_packets.begin(); it != unacked_packets.end(); ) {
            auto& packet_info = it->second;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - packet_info.second).count() > UDPS_TIMEOUT_MS) {
                // Packet timed out, retransmit
                log_message(RED, "Client: Retransmitting DATA (Seq: " + std::to_string(packet_info.first.seq) + ") due to timeout.");
                std::vector<char> data_buffer = serialize_packet(packet_info.first);
                sendto(client_sock, data_buffer.data(), data_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);

                // BBR: Timeout detected, reset to STARTUP (simplified)
                bbr_state = STARTUP;
                bbr_current_gain = 2.89;
                min_rtt_us = 0; // Reset min RTT on loss
                delivery_rate_bytes_per_ms = 0.0;
                log_message(RED, "Client: Timeout detected. BBR State reset to STARTUP.");

                packet_info.second = now; // Reset timer for retransmitted packet
                ++it;
            } else {
                ++it;
            }
        }
    }

    // Simplified BBR state update logic
    void update_bbr_state() {
        auto now = std::chrono::steady_clock::now();
        long long duration_since_last_update_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_delivery_rate_update_time).count();

        if (duration_since_last_update_ms > 100) { // Update rate every 100ms
            if (bytes_acked_since_last_rate_update > 0 && duration_since_last_update_ms > 0) {
                delivery_rate_bytes_per_ms = (double)bytes_acked_since_last_rate_update / duration_since_last_update_ms;
                log_message(MAGENTA, "Client: Estimated Delivery Rate: " + std::to_string(delivery_rate_bytes_per_ms) + " B/ms");
            }
            bytes_acked_since_last_rate_update = 0;
            last_delivery_rate_update_time = now;
        }

        // State machine (simplified)
        switch (bbr_state) {
            case STARTUP:
                bbr_current_gain = 2.89; // High gain for bandwidth discovery
                // Transition to DRAIN if min_rtt is stable and delivery rate is estimated
                if (min_rtt_us > 0 && delivery_rate_bytes_per_ms > 0.1 && bytes_in_flight > UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    bbr_state = DRAIN;
                    bbr_current_gain = 1.0 / 2.89; // Drain gain
                    log_message(MAGENTA, "Client: BBR State: DRAIN");
                }
                break;
            case DRAIN:
                // Transition to PROBE_BW when inflight bytes fall below target (simplified)
                // Target inflight is BtlBW * min_rtt * 1.0
                if (bytes_in_flight <= (delivery_rate_bytes_per_ms * min_rtt_us / 1000.0 * 1.0) && min_rtt_us > 0) {
                    bbr_state = PROBE_BW;
                    bbr_probe_gain_cycle_index = 0;
                    bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                    last_rtt_probe_time = now; // Reset for ProbeBW cycling
                    log_message(MAGENTA, "Client: BBR State: PROBE_BW");
                }
                break;
            case PROBE_BW:
                // Cycle through gains over an RTT (simplified: fixed time)
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rtt_probe_time).count() > (min_rtt_us / 1000.0 * 2)) { // Cycle every ~2 RTTs
                     bbr_probe_gain_cycle_index = (bbr_probe_gain_cycle_index + 1) % bbr_gains.size();
                     bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                     last_rtt_probe_time = now;
                     log_message(MAGENTA, "Client: BBR State: PROBE_BW, New Gain: " + std::to_string(bbr_current_gain));
                }
                // Check for PROBE_RTT periodically
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rtt_probe_time).count() > rtt_probe_interval_ms) {
                    bbr_state = PROBE_RTT;
                    bbr_probe_rtt_start_time = now; // Corrected: this member is now declared
                    log_message(MAGENTA, "Client: BBR State: PROBE_RTT");
                }
                break;
            case PROBE_RTT:
                // Reduce inflight to find min_rtt
                // Limit inflight to 4 packets (or minimum necessary)
                // This state is primarily about finding the true min_rtt by emptying the pipe.
                // We'll just transition back after a fixed duration for this demo.
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - bbr_probe_rtt_start_time).count() > rtt_probe_duration_ms) {
                    bbr_state = PROBE_BW; // Go back to probing bandwidth
                    bbr_probe_gain_cycle_index = 0;
                    bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                    log_message(MAGENTA, "Client: BBR State: PROBE_BW (from PROBE_RTT)");
                }
                break;
        }

        // Calculate pacing rate
        if (min_rtt_us > 0 && delivery_rate_bytes_per_ms > 0) {
            pacing_rate_bytes_per_ms = delivery_rate_bytes_per_ms * bbr_current_gain;
        } else {
            // Default pacing rate if no estimates yet (e.g., during initial handshake)
            pacing_rate_bytes_per_ms = (double)PAYLOAD_BUFFER_SIZE / (UDPS_TIMEOUT_MS / 2.0); // Send 2 packets per timeout initially
        }
        if (pacing_rate_bytes_per_ms < 0.1) pacing_rate_bytes_per_ms = 0.1; // Minimum pacing rate to avoid division by zero
    }


public:
    UDPSClient(const std::string& key = "") :
        client_sock(UDPS_INVALID_SOCKET),
        current_conn_id(0),
        next_seq_num(1), // Start sequence numbers from 1
        expected_ack_num(0),
        encryption_key(key),
        client_private_key("client_priv_key_123"), // Example private key for conceptual DH
        connected(false),
        // BBR initializations
        bbr_state(STARTUP),
        min_rtt_us(0),
        delivery_rate_bytes_per_ms(0.0),
        bytes_acked_since_last_rate_update(0),
        bytes_in_flight(0),
        pacing_rate_bytes_per_ms(0.0), // Will be set by update_bbr_state
        bbr_current_gain(2.89), // Initial Startup gain
        bbr_probe_gain_cycle_index(0),
        rtt_probe_interval_ms(10000), // 10 seconds
        rtt_probe_duration_ms(200), // 200 ms
        last_sent_packet_time_us(0),
        bbr_probe_rtt_start_time(std::chrono::steady_clock::now()) // Initialize the new member
        {
        #ifdef _WIN32
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != 0) {
                log_message(RED, "WSAStartup failed: " + std::to_string(iResult));
                exit(EXIT_FAILURE);
            }
        #endif
        srand(static_cast<unsigned int>(time(0)));
        last_delivery_rate_update_time = std::chrono::steady_clock::now();
        last_rtt_probe_time = std::chrono::steady_clock::now();
    }

    ~UDPSClient() {
        if (client_sock != UDPS_INVALID_SOCKET) {
            UDPS_CLOSE_SOCKET(client_sock);
        }
        #ifdef _WIN32
            WSACleanup();
        #endif
    }

    bool is_connected() const {
        return connected.load();
    }

    // Connect to the server using a 4-way handshake
    bool connect_to_server(const std::string& ip, int port) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_DGRAM; // UDP socket

        std::string port_str = std::to_string(port);
        int status = getaddrinfo(ip.c_str(), port_str.c_str(), &hints, &res);
        if (status != 0) {
            log_message(RED, "Client: Getaddrinfo failed: " + std::string(gai_strerror(status)));
            return false;
        }

        client_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (client_sock == UDPS_INVALID_SOCKET) {
            log_message(RED, "Client: Socket creation failed.");
            freeaddrinfo(res);
            return false;
        }

        // Store server address info
        memcpy(&server_addr_storage, res->ai_addr, res->ai_addrlen);
        server_addr_len = res->ai_addrlen;
        freeaddrinfo(res); // Free the address info structure

        log_message(CYAN, "Client: Attempting to connect to " + sockaddr_to_string(&server_addr_storage, server_addr_len));

        // --- Handshake Step 1: Send SYN (ClientHello) ---
        UDPSPacket syn_packet;
        uint32_t syn_packet_seq_sent = next_seq_num; // Store the sequence number used for THIS SYN
        syn_packet.flag = SYN;
        syn_packet.seq = syn_packet_seq_sent;
        // Client's conceptual public key sent in SYN payload
        std::string client_public_key_dummy = "client_pub_key_abc";
        if (client_public_key_dummy.length() > PAYLOAD_BUFFER_SIZE) {
            log_message(RED, "Client: Dummy public key too long for SYN payload.");
            UDPS_CLOSE_SOCKET(client_sock);
            client_sock = UDPS_INVALID_SOCKET;
            return false;
        }
        syn_packet.length = static_cast<uint16_t>(client_public_key_dummy.length());
        memcpy(syn_packet.data, client_public_key_dummy.c_str(), syn_packet.length);

        std::vector<char> syn_buffer = serialize_packet(syn_packet);

        int retries = 0;
        while (retries < UDPS_MAX_RETRIES) {
            log_message(CYAN, "Client: Sending SYN (Seq: " + std::to_string(syn_packet.seq) + ") - Attempt " + std::to_string(retries + 1));
            if (sendto(client_sock, syn_buffer.data(), syn_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len) == UDPS_SOCKET_ERROR) {
                log_message(RED, "Client: Send SYN failed.");
                UDPS_CLOSE_SOCKET(client_sock);
                client_sock = UDPS_INVALID_SOCKET;
                return false;
            }
            // next_seq_num is NOT incremented here. It represents the next available seq for a *new* packet.
            // The SYN packet consumes 'syn_packet_seq_sent'. The next packet will be syn_packet_seq_sent + 1.

            // --- Handshake Step 2: Wait for SYN-ACK (ServerHello) ---
            set_socket_timeout(UDPS_TIMEOUT_MS);
            char recv_buf[MAX_PACKET_SIZE];
            sockaddr_storage temp_addr_storage;
            socklen_t temp_addr_len = sizeof(temp_addr_storage);
            int bytes_received = recvfrom(client_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                         (struct sockaddr*)&temp_addr_storage, &temp_addr_len);

            if (bytes_received == UDPS_SOCKET_ERROR) {
                #ifdef _WIN32
                    if (WSAGetLastError() == WSAETIMEDOUT) {
                        log_message(YELLOW, "Client: SYN-ACK timeout. Retrying...");
                    } else {
                        log_message(RED, "Client: Recvfrom error during SYN-ACK: " + std::to_string(WSAGetLastError()));
                        UDPS_CLOSE_SOCKET(client_sock);
                        client_sock = UDPS_INVALID_SOCKET;
                        return false;
                    }
                #else
                    if (errno == EWOULDBLOCK || errno == EAGAIN) { // Timeout
                        log_message(YELLOW, "Client: SYN-ACK timeout. Retrying...");
                    } else {
                        perror(RED "Client: Recvfrom error during SYN-ACK");
                        UDPS_CLOSE_SOCKET(client_sock);
                        client_sock = UDPS_INVALID_SOCKET;
                        return false;
                    }
                #endif
                retries++;
                continue;
            }

            UDPSPacket syn_ack_packet = deserialize_packet(recv_buf);

            // Validate SYN-ACK: Check flag and if server's ACK acknowledges the specific SYN we just sent
            if (syn_ack_packet.flag == ACK && syn_ack_packet.ack == (syn_packet_seq_sent + 1)) { // THIS IS THE CRITICAL FIX
                current_conn_id = syn_ack_packet.conn_id;
                expected_ack_num = syn_ack_packet.seq + 1; // Server's SYN-ACK seq + 1
                log_message(GREEN, "Client: Received SYN-ACK (ConnID: " + std::to_string(current_conn_id) +
                                   ", Seq: " + std::to_string(syn_ack_packet.seq) +
                                   ", Ack: " + std::to_string(syn_ack_packet.ack) + ")");

                // Conceptual Key Exchange: Derive shared secret from server's public key (in payload)
                std::string server_public_key_from_server(syn_ack_packet.data, syn_ack_packet.length);
                if (!encryption_key.empty()) { // Only if encryption is enabled
                    encryption_key = generate_shared_secret(client_private_key, server_public_key_from_server);
                    log_message(MAGENTA, "Client: Derived shared encryption key (conceptual).");
                }

                // --- Handshake Step 3: Send Handshake Finished ACK ---
                UDPSPacket handshake_ack_packet;
                handshake_ack_packet.flag = ACK;
                handshake_ack_packet.conn_id = current_conn_id;
                handshake_ack_packet.seq = syn_packet_seq_sent + 1; // This is the next sequence after the SYN (i.e., 2)
                handshake_ack_packet.ack = expected_ack_num; // Acknowledging server's SYN-ACK
                
                // Add "HANDSHAKE_FINISHED" message to payload
                if (HANDSHAKE_FINISHED_MSG.length() > PAYLOAD_BUFFER_SIZE) {
                    log_message(RED, "Client: Handshake finished message too long.");
                    UDPS_CLOSE_SOCKET(client_sock);
                    client_sock = UDPS_INVALID_SOCKET;
                    return false;
                }
                handshake_ack_packet.length = static_cast<uint16_t>(HANDSHAKE_FINISHED_MSG.length());
                memcpy(handshake_ack_packet.data, HANDSHAKE_FINISHED_MSG.c_str(), HANDSHAKE_FINISHED_MSG.length());

                std::vector<char> handshake_ack_buffer = serialize_packet(handshake_ack_packet);

                log_message(GREEN, "Client: Sending Handshake Finished ACK (ConnID: " + std::to_string(current_conn_id) +
                                   ", Seq: " + std::to_string(handshake_ack_packet.seq) +
                                   ", Ack: " + std::to_string(handshake_ack_packet.ack) + ")");
                if (sendto(client_sock, handshake_ack_buffer.data(), handshake_ack_buffer.size(), 0,
                           (struct sockaddr*)&server_addr_storage, server_addr_len) == UDPS_SOCKET_ERROR) {
                    log_message(RED, "Client: Send Handshake Finished ACK failed.");
                    UDPS_CLOSE_SOCKET(client_sock);
                    client_sock = UDPS_INVALID_SOCKET;
                    return false;
                }

                next_seq_num = syn_packet_seq_sent + 2; // Update next_seq_num for subsequent DATA packets (e.g., 3)
                connected.store(true); // Client considers itself connected after sending Handshake Finished
                log_message(GREEN, "Client: Connection established (Handshake Step 3 complete) with ConnID: " + std::to_string(current_conn_id));
                
                // Add a small delay to allow server to process the final handshake ACK
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Give server time to update state
                
                return true; // Client is ready to send data
            } else {
                log_message(YELLOW, "Client: Received unexpected packet during handshake (Flag: " +
                                    std::to_string(syn_ack_packet.flag) + ", Ack: " +
                                    std::to_string(syn_ack_packet.ack) + "). Expected Ack for " +
                                    std::to_string(syn_packet_seq_sent + 1) + ". Retrying...");
                retries++;
            }
        }

        log_message(RED, "Client: Failed to establish connection after " + std::to_string(UDPS_MAX_RETRIES) + " retries.");
        UDPS_CLOSE_SOCKET(client_sock);
        client_sock = UDPS_INVALID_SOCKET;
        return false;
    }

    // Send data using the established connection
    bool send_data(const std::string& message) {
        if (!connected.load()) {
            log_message(RED, "Client: Not connected to server. Call connect() first.");
            return false;
        }
        if (message.length() > PAYLOAD_BUFFER_SIZE) {
            log_message(RED, "Client: Message too long. Max " + std::to_string(PAYLOAD_BUFFER_SIZE) + " bytes.");
            return false;
        }

        std::unique_lock<std::mutex> unacked_lk(unacked_mutex);
        // BBR-inspired pacing and inflight limit
        long long time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - last_sent_packet_time_us;
        long long pacing_delay_us = (long long)(PAYLOAD_BUFFER_SIZE / pacing_rate_bytes_per_ms * 1000.0); // Time to wait before sending next packet

        // Always update BBR state before attempting to send data
        update_bbr_state(); // Moved here to ensure pacing_rate_bytes_per_ms is updated

        // Calculate target inflight, ensuring a minimum window
        double target_inflight = (delivery_rate_bytes_per_ms * min_rtt_us / 1000.0 * bbr_current_gain);
        if (target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
            target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
        }

        // Wait if too much data in flight OR if pacing dictates
        while (bytes_in_flight >= target_inflight || // Inflight limit
               (time_since_last_sent_us < pacing_delay_us && pacing_rate_bytes_per_ms > 0.0))
        {
            unacked_lk.unlock();
            log_message(YELLOW, "Client: Pacing/Inflight limit. Waiting... (Inflight: " + std::to_string(bytes_in_flight) + " bytes, Pacing: " + std::to_string(pacing_rate_bytes_per_ms) + " B/ms)");
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            unacked_lk.lock();
            if (!connected.load()) return false;
            time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - last_sent_packet_time_us;
        }

        UDPSPacket data_packet;
        data_packet.flag = DATA;
        data_packet.conn_id = current_conn_id;
        data_packet.seq = next_seq_num;
        data_packet.ack = expected_ack_num; // Acknowledge the last received packet from server
        data_packet.length = static_cast<uint16_t>(message.length());
        memcpy(data_packet.data, message.c_str(), message.length());

        // Apply pseudo-encryption (using the derived key)
        if (!encryption_key.empty()) {
            xor_encrypt_decrypt(data_packet.data, data_packet.length, encryption_key);
            log_message(MAGENTA, "Client: Encrypted outgoing data.");
        }

        std::vector<char> data_buffer = serialize_packet(data_packet);

        log_message(BLUE, "Client: Sending DATA (ConnID: " + std::to_string(data_packet.conn_id) +
                           ", Seq: " + std::to_string(data_packet.seq) +
                           ", Ack: " + std::to_string(data_packet.ack) +
                           ", Len: " + std::to_string(data_packet.length) + ")");
        if (sendto(client_sock, data_buffer.data(), data_buffer.size(), 0,
                   (struct sockaddr*)&server_addr_storage, server_addr_len) == UDPS_SOCKET_ERROR) {
            log_message(RED, "Client: Send DATA failed.");
            return false;
        }

        // Add to unacked packets and increment sequence number
        unacked_packets[next_seq_num] = {data_packet, std::chrono::steady_clock::now()};
        bytes_in_flight += data_packet.length;
        next_seq_num++;
        last_sent_packet_time_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        return true;
    }

    // Receive data from the server and process ACKs
    std::string receive_data() {
        if (!connected.load()) {
            return "";
        }

        // Handle retransmissions periodically
        handle_retransmissions();
        update_bbr_state(); // Update BBR state periodically

        set_socket_timeout(10); // Short timeout for non-blocking receive check
        char recv_buf[MAX_PACKET_SIZE];
        sockaddr_storage temp_addr_storage;
        socklen_t temp_addr_len = sizeof(temp_addr_storage);
        int bytes_received = recvfrom(client_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                     (struct sockaddr*)&temp_addr_storage, &temp_addr_len);

        if (bytes_received == UDPS_SOCKET_ERROR) {
            #ifdef _WIN32
                if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK) {
                    // No data available, not an error for non-blocking check
                    return "";
                } else {
                    log_message(RED, "Client: Recvfrom error during receive: " + std::to_string(WSAGetLastError()));
                    return "";
                }
            #else
                if (errno == EWOULDBLOCK || errno == EAGAIN) {
                    // No data available
                    return "";
                } else {
                    perror(RED "Client: Recvfrom error during receive");
                    return "";
                }
            #endif
        }

        UDPSPacket received_packet = deserialize_packet(recv_buf);

        if (received_packet.conn_id != current_conn_id) {
            log_message(YELLOW, "Client: Received packet with unknown ConnID: " + std::to_string(received_packet.conn_id));
            return ""; // Ignore packets for other connections
        }

        if (received_packet.flag == DATA) {
            std::lock_guard<std::mutex> lock(receive_mutex);
            // Packet Reordering Buffer logic
            if (received_packet.seq == expected_ack_num) {
                // In-order packet
                // Apply pseudo-decryption
                if (!encryption_key.empty()) {
                    xor_encrypt_decrypt(received_packet.data, received_packet.length, encryption_key);
                    log_message(MAGENTA, "Client: Decrypted incoming data.");
                }
                received_messages_queue.push(std::string(received_packet.data, received_packet.length));
                expected_ack_num++;

                // Deliver buffered packets that are now in order
                while (reorder_buffer.count(expected_ack_num)) {
                    UDPSPacket& buffered_packet = reorder_buffer[expected_ack_num];
                    if (!encryption_key.empty()) {
                        xor_encrypt_decrypt(buffered_packet.data, buffered_packet.length, encryption_key);
                        log_message(MAGENTA, "Client: Decrypted buffered incoming data.");
                    }
                    received_messages_queue.push(std::string(buffered_packet.data, buffered_packet.length));
                    reorder_buffer.erase(expected_ack_num);
                    expected_ack_num++;
                }

                log_message(BLUE, "Client: Received DATA (ConnID: " + std::to_string(received_packet.conn_id) +
                                   ", Seq: " + std::to_string(received_packet.seq) +
                                   ", Ack: " + std::to_string(received_packet.ack) +
                                   ", Len: " + std::to_string(received_packet.length) +
                                   ")");

                // Send ACK for received DATA
                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = (rand() % 1000) + 1; // Server's sequence for this ACK
                ack_packet.ack = expected_ack_num;
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
                log_message(GREEN, "Client: Sent ACK for DATA (ConnID: " + std::to_string(ack_packet.conn_id) +
                                   ", Seq: " + std::to_string(ack_packet.seq) +
                                   ", Ack: " + std::to_string(ack_packet.ack) + ")");

            } else if (received_packet.seq > expected_ack_num) {
                // Out-of-order packet, buffer it
                log_message(YELLOW, "Client: Received out-of-order DATA packet (Seq: " + std::to_string(received_packet.seq) +
                                    ", Expected: " + std::to_string(expected_ack_num) + "). Buffering.");
                reorder_buffer[received_packet.seq] = received_packet;
                // Still send ACK for the highest in-order sequence received + 1 (cumulative ACK)
                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = next_seq_num++; // client’s own next sequence number
                ack_packet.ack = expected_ack_num; // Still acknowledge what we've received contiguously
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
                log_message(GREEN, "Client: Sent ACK for out-of-order DATA (ConnID: " + std::to_string(ack_packet.conn_id) +
                                   ", Seq: " + std::to_string(ack_packet.seq) +
                                   ", Ack: " + std::to_string(ack_packet.ack) + ").");
            } else { // received_packet.seq < expected_ack_num (duplicate)
                log_message(YELLOW, "Client: Received duplicate DATA packet (Seq: " + std::to_string(received_packet.seq) +
                                    ", Expected ACK: " + std::to_string(expected_ack_num) + "). Sending ACK again.");
                // Resend ACK for duplicate
                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = next_seq_num;
                ack_packet.ack = received_packet.seq + 1; // Acknowledge the received sequence
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
            }

            // Return message from the queue if available
            if (!received_messages_queue.empty()) {
                std::string msg = received_messages_queue.front();
                received_messages_queue.pop();
                return msg;
            }
            return "";

        } else if (received_packet.flag == ACK) {
            // Check if this ACK is the final ACK from the server in the 4-way handshake
            // This check should ideally be done before processing as a general ACK
            // to ensure handshake state is handled correctly.
            // If the client is not yet connected, and this ACK acknowledges the Handshake Finished message
            if (!connected.load()) { // This means client has sent Step 3 and is waiting for Step 4
                // It acknowledges the client's Handshake Finished message (which had seq = next_seq_num - 1)
                if (received_packet.ack == (next_seq_num)) { // next_seq_num is client's seq for Handshake Finished + 1
                    log_message(GREEN, "Client: Received final ACK from server (Handshake Step 4 complete).");
                    // connected.store(true) is already set after sending Handshake Finished (Step 3)
                } else {
                    log_message(YELLOW, "Client: Received unexpected ACK during final handshake phase (Ack: " + std::to_string(received_packet.ack) + ", Expected: " + std::to_string(next_seq_num) + ").");
                }
            }
            process_ack(received_packet.ack); // Process ACK for congestion control
            log_message(GREEN, "Client: Received ACK (ConnID: " + std::to_string(received_packet.conn_id) +
                               ", Seq: " + std::to_string(received_packet.seq) +
                               ", Ack: " + std::to_string(received_packet.ack) + ").");
            return "";
        } else if (received_packet.flag == FIN) {
            log_message(YELLOW, "Client: Received FIN from server. Initiating graceful shutdown.");
            connected.store(false);
            // Send FIN-ACK
            UDPSPacket fin_ack_packet;
            fin_ack_packet.flag = FIN_ACK;
            fin_ack_packet.conn_id = current_conn_id;
            fin_ack_packet.seq = next_seq_num;
            fin_ack_packet.ack = expected_ack_num; // instead of received_packet.seq + 1
            std::vector<char> fin_ack_buffer = serialize_packet(fin_ack_packet);
            sendto(client_sock, fin_ack_buffer.data(), fin_ack_buffer.size(), 0,
                   (struct sockaddr*)&server_addr_storage, server_addr_len);
            log_message(GREEN, "Client: Sent FIN-ACK.");
            close_connection();
            return "[SERVER_CLOSED]"; // Special message to indicate server closed
        } else if (received_packet.flag == PING) {
            log_message(CYAN, "Client: Received PING from server (ConnID: " + std::to_string(received_packet.conn_id) + "). Sending PING-ACK.");
            UDPSPacket ping_ack_packet;
            ping_ack_packet.flag = ACK;
            ping_ack_packet.conn_id = current_conn_id;
            ping_ack_packet.seq = next_seq_num;
            ping_ack_packet.ack = expected_ack_num; // instead of received_packet.seq + 1
            std::vector<char> ping_ack_buffer = serialize_packet(ping_ack_packet);
            sendto(client_sock, ping_ack_buffer.data(), ping_ack_buffer.size(), 0,
                   (struct sockaddr*)&server_addr_storage, server_addr_len);
            return "";
        }
        else {
            log_message(YELLOW, "Client: Received unknown packet flag: " + std::to_string(received_packet.flag));
            return "";
        }
    }

    // Close the connection gracefully
    void close_connection() {
        if (!connected.load()) {
            log_message(YELLOW, "Client: Not connected, no need to close gracefully.");
            if (client_sock != UDPS_INVALID_SOCKET) {
                UDPS_CLOSE_SOCKET(client_sock);
                client_sock = UDPS_INVALID_SOCKET;
            }
            return;
        }

        log_message(CYAN, "Client: Initiating graceful shutdown (sending FIN).");
        UDPSPacket fin_packet;
        fin_packet.flag = FIN;
        fin_packet.conn_id = current_conn_id;
        fin_packet.seq = next_seq_num;
        fin_packet.ack = expected_ack_num;
        std::vector<char> fin_buffer = serialize_packet(fin_packet);

        int retries = 0;
        while (retries < UDPS_MAX_RETRIES) {
            log_message(CYAN, "Client: Sending FIN (Seq: " + std::to_string(fin_packet.seq) + ") - Attempt " + std::to_string(retries + 1));
            if (sendto(client_sock, fin_buffer.data(), fin_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len) == UDPS_SOCKET_ERROR) {
                log_message(RED, "Client: Send FIN failed.");
                break; // Don't retry if send itself fails
            }

            // Wait for FIN-ACK
            set_socket_timeout(UDPS_TIMEOUT_MS);
            char recv_buf[MAX_PACKET_SIZE];
            sockaddr_storage temp_addr_storage;
            socklen_t temp_addr_len = sizeof(temp_addr_storage);
            int bytes_received = recvfrom(client_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                         (struct sockaddr*)&temp_addr_storage, &temp_addr_len);

            if (bytes_received == UDPS_SOCKET_ERROR) {
                #ifdef _WIN32
                    if (WSAGetLastError() == WSAETIMEDOUT) {
                        log_message(YELLOW, "Client: FIN-ACK timeout. Retrying...");
                    } else {
                        log_message(RED, "Client: Recvfrom error during FIN-ACK: " + std::to_string(WSAGetLastError()));
                        break;
                    }
                #else
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        log_message(YELLOW, "Client: FIN-ACK timeout. Retrying...");
                    } else {
                        perror(RED "Client: Recvfrom error during FIN-ACK");
                        break;
                    }
                #endif
                retries++;
                continue;
            }

            UDPSPacket fin_ack_response = deserialize_packet(recv_buf);
            if (fin_ack_response.flag == ACK && fin_ack_response.conn_id == current_conn_id &&
                fin_ack_response.ack == (next_seq_num + 1)) {
                log_message(GREEN, "Client: Received FIN-ACK. Connection gracefully closed.");
                connected.store(false);
                break;
            } else {
                log_message(YELLOW, "Client: Received unexpected packet for FIN-ACK. Retrying...");
                retries++;
            }
        }

        if (client_sock != UDPS_INVALID_SOCKET) {
            UDPS_CLOSE_SOCKET(client_sock);
            client_sock = UDPS_INVALID_SOCKET;
        }
        connected.store(false);
    }
};

// --- UDPS Server Class ---
class UDPSServer {
public: // Changed to public for main() access
    UDPS_SOCKET server_sock;
private:
    sockaddr_storage server_addr_storage; // Use sockaddr_storage for IPv4/IPv6
    socklen_t server_addr_len;
    std::string encryption_key_base; // This is the base key, will be derived for each client
    std::string server_private_key; // For conceptual key exchange
    std::atomic<bool> running;
    uint16_t next_conn_id;

    // Structure to hold client-specific information and communication channels
    struct ClientInfo {
        uint16_t conn_id; // Added missing member
        sockaddr_storage addr; // Use sockaddr_storage for IPv4/IPv6
        socklen_t addr_len;
        uint32_t next_expected_seq; // Next sequence number expected from client
        uint32_t last_sent_seq;     // Last sequence number sent to client
        std::chrono::steady_clock::time_point last_activity;
        enum State { HANDSHAKE_SYN_RECEIVED, CONNECTED, FIN_RECEIVED } state;
        std::string client_public_key_for_dh; // Store client's public key for DH
        std::string derived_encryption_key; // Per-client derived key

        // For multi-threading and packet processing
        std::atomic<bool> handler_running; // Added missing member
        std::thread handler_thread;       // Added missing member
        std::queue<UDPSPacket> incoming_packet_queue; // Added missing member
        std::mutex incoming_queue_mutex;              // Added missing member
        std::condition_variable incoming_queue_cv;    // Added missing member

        // For sending data to client from server's perspective (e.g., echo)
        std::queue<std::string> outgoing_message_queue; // Added missing member
        std::mutex outgoing_queue_mutex;                // Added missing member
        std::condition_variable outgoing_queue_cv;      // Added missing member

        // BBR-inspired Congestion Control variables for server sending to client
        enum BBRState { STARTUP, DRAIN, PROBE_BW, PROBE_RTT };
        BBRState bbr_state;
        long long min_rtt_us; // Minimum RTT observed in microseconds
        double delivery_rate_bytes_per_ms; // Estimated bandwidth in bytes/ms
        std::chrono::steady_clock::time_point last_delivery_rate_update_time;
        size_t bytes_acked_since_last_rate_update;
        size_t bytes_in_flight; // Total bytes sent but not yet ACKed
        double pacing_rate_bytes_per_ms; // Rate at which to send bytes
        double bbr_current_gain; // Current gain factor for pacing and inflight window
        std::vector<double> bbr_gains = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}; // Simplified cycle for ProbeBW
        int bbr_probe_gain_cycle_index;
        std::chrono::steady_clock::time_point last_rtt_probe_time;
        long long rtt_probe_interval_ms; // How often to enter PROBE_RTT state
        long long rtt_probe_duration_ms; // How long to stay in PROBE_RTT state
        long long last_sent_packet_time_us; // For pacing control
        std::chrono::steady_clock::time_point bbr_probe_rtt_start_time; // Added missing member


        std::map<uint32_t, std::pair<UDPSPacket, std::chrono::steady_clock::time_point>> unacked_packets;
        std::mutex unacked_mutex;

        // Packet Reordering Buffer for server receiving from client
        std::map<uint32_t, UDPSPacket> reorder_buffer;
        std::queue<std::string> delivered_messages; // Messages ready for server application to consume
        std::mutex reorder_buffer_mutex;


        ClientInfo(sockaddr_storage a, socklen_t al) :
            conn_id(0), // Initialize conn_id
            addr(a), addr_len(al), next_expected_seq(1), last_sent_seq(0),
            last_activity(std::chrono::steady_clock::now()), state(HANDSHAKE_SYN_RECEIVED),
            handler_running(true), // Initialized
            // BBR initializations for server's outgoing
            bbr_state(STARTUP),
            min_rtt_us(0),
            delivery_rate_bytes_per_ms(0.0),
            bytes_acked_since_last_rate_update(0),
            bytes_in_flight(0),
            pacing_rate_bytes_per_ms(0.0),
            bbr_current_gain(2.89),
            bbr_probe_gain_cycle_index(0),
            rtt_probe_interval_ms(10000),
            rtt_probe_duration_ms(200),
            last_sent_packet_time_us(0),
            bbr_probe_rtt_start_time(std::chrono::steady_clock::now()) // Initialize
            {
                last_delivery_rate_update_time = std::chrono::steady_clock::now();
                last_rtt_probe_time = std::chrono::steady_clock::now();
            }

        // Destructor to ensure thread is joined
        ~ClientInfo() {
            if (handler_thread.joinable()) { // Corrected: handler_thread is now a member
                handler_thread.join();
            }
        }
    };

public: // Changed to public for main() access
    std::map<uint16_t, ClientInfo> clients;
    std::mutex clients_mutex; // Mutex to protect clients map
    std::thread cleanup_thread; // Dedicated thread for cleanup

private: // Rest of the private members
    // Helper to set socket timeout for recvfrom
    void set_socket_timeout(int ms) {
        #ifdef _WIN32
            DWORD timeout = ms;
            setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        #else
            struct timeval tv;
            tv.tv_sec = ms / 1000;
            tv.tv_usec = (ms % 1000) * 1000;
            setsockopt(server_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        #endif
    }

    // Process incoming ACKs for congestion control (server's perspective for its outgoing data)
    void server_process_ack(ClientInfo& client, uint32_t ack_num) {
        std::lock_guard<std::mutex> lock(client.unacked_mutex);
        // Remove packets that are acknowledged. ack_num acknowledges up to ack_num - 1.
        auto it = client.unacked_packets.begin();
        while (it != client.unacked_packets.end() && it->first < ack_num) {
            log_message(MAGENTA, "Server Handler: ACKed packet (Seq: " + std::to_string(it->first) + ") for ConnID " + std::to_string(client.conn_id) + ". Removing from unacked queue.");
            
            // Update RTT and delivery rate estimates
            auto now = std::chrono::steady_clock::now();
            long long current_rtt_us = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second.second).count();
            if (client.min_rtt_us == 0 || current_rtt_us < client.min_rtt_us) {
                client.min_rtt_us = current_rtt_us;
                log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " New Min RTT: " + std::to_string(client.min_rtt_us) + " us");
            }
            
            client.bytes_acked_since_last_rate_update += it->second.first.length;
            client.bytes_in_flight -= it->second.first.length;

            it = client.unacked_packets.erase(it);
        }
        server_update_bbr_state(client); // Update BBR state after processing ACKs
    }

    // Simplified BBR state update logic for server's outgoing traffic
    void server_update_bbr_state(ClientInfo& client) {
        auto now = std::chrono::steady_clock::now();
        long long duration_since_last_update_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_delivery_rate_update_time).count();

        if (duration_since_last_update_ms > 100) { // Update rate every 100ms
            if (client.bytes_acked_since_last_rate_update > 0 && duration_since_last_update_ms > 0) {
                client.delivery_rate_bytes_per_ms = (double)client.bytes_acked_since_last_rate_update / duration_since_last_update_ms;
                log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " Estimated Delivery Rate: " + std::to_string(client.delivery_rate_bytes_per_ms) + " B/ms");
            }
            client.bytes_acked_since_last_rate_update = 0;
            client.last_delivery_rate_update_time = now;
        }

        // State machine (simplified)
        switch (client.bbr_state) {
            case ClientInfo::STARTUP: // Qualified enum
                client.bbr_current_gain = 2.89; // High gain for bandwidth discovery
                // Transition to DRAIN if min_rtt is stable and delivery rate is estimated
                if (client.min_rtt_us > 0 && client.delivery_rate_bytes_per_ms > 0.1 && client.bytes_in_flight > UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    client.bbr_state = ClientInfo::DRAIN; // Qualified enum
                    client.bbr_current_gain = 1.0 / 2.89; // Drain gain
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: DRAIN");
                }
                break;
            case ClientInfo::DRAIN: // Qualified enum
                // Transition to PROBE_BW when inflight bytes fall below target (simplified)
                if (client.bytes_in_flight <= (client.delivery_rate_bytes_per_ms * client.min_rtt_us / 1000.0 * 1.0) && client.min_rtt_us > 0) {
                    client.bbr_state = ClientInfo::PROBE_BW; // Qualified enum
                    client.bbr_probe_gain_cycle_index = 0;
                    client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                    client.last_rtt_probe_time = now; // Reset for ProbeBW cycling
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW");
                }
                break;
            case ClientInfo::PROBE_BW: // Qualified enum
                // Cycle through gains over an RTT (simplified: fixed time)
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_rtt_probe_time).count() > (client.min_rtt_us / 1000.0 * 2)) { // Cycle every ~2 RTTs
                     client.bbr_probe_gain_cycle_index = (client.bbr_probe_gain_cycle_index + 1) % client.bbr_gains.size();
                     client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                     client.last_rtt_probe_time = now;
                     log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW, New Gain: " + std::to_string(client.bbr_current_gain));
                }
                // Check for PROBE_RTT periodically
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_rtt_probe_time).count() > client.rtt_probe_interval_ms) {
                    client.bbr_state = ClientInfo::PROBE_RTT; // Qualified enum
                    client.bbr_probe_rtt_start_time = now;
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_RTT");
                }
                break;
            case ClientInfo::PROBE_RTT: // Qualified enum
                // Reduce inflight to find min_rtt
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.bbr_probe_rtt_start_time).count() > client.rtt_probe_duration_ms) {
                    client.bbr_state = ClientInfo::PROBE_BW; // Go back to probing bandwidth // Qualified enum
                    client.bbr_probe_gain_cycle_index = 0;
                    client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW (from PROBE_RTT)");
                }
                break;
        }

        // Calculate pacing rate
        if (client.min_rtt_us > 0 && client.delivery_rate_bytes_per_ms > 0) {
            client.pacing_rate_bytes_per_ms = client.delivery_rate_bytes_per_ms * client.bbr_current_gain;
        } else {
            client.pacing_rate_bytes_per_ms = (double)PAYLOAD_BUFFER_SIZE / (UDPS_TIMEOUT_MS / 2.0); // Default to 2 packets per timeout initially
        }
        if (client.pacing_rate_bytes_per_ms < 0.1) client.pacing_rate_bytes_per_ms = 0.1; // Minimum pacing rate
    }

    // Per-client handler loop
    void client_handler_loop(uint16_t conn_id, UDPS_SOCKET server_socket_fd, const std::string& server_private_key_base) {
        ClientInfo* client_ptr = nullptr;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            auto it = clients.find(conn_id);
            if (it == clients.end()) {
                log_message(RED, "Server Handler: Client " + std::to_string(conn_id) + " not found. Exiting handler thread.");
                return;
            }
            client_ptr = &(it->second);
        }
        ClientInfo& client = *client_ptr; // Use reference for easier access
        client.conn_id = conn_id; // Set the conn_id in the ClientInfo struct

        log_message(CYAN, "Server Handler: Client handler thread started for ConnID: " + std::to_string(conn_id));

        while (client.handler_running.load()) {
            // --- Process Incoming Packets for this client ---
            UDPSPacket received_packet;
            bool packet_available = false;
            {
                std::unique_lock<std::mutex> incoming_lk(client.incoming_queue_mutex);
                // Wait for a packet or for the handler to stop
                client.incoming_queue_cv.wait_for(incoming_lk, std::chrono::milliseconds(100),
                                                  [&]{ return !client.incoming_packet_queue.empty() || !client.handler_running.load(); });

                if (!client.incoming_packet_queue.empty()) {
                    received_packet = client.incoming_packet_queue.front();
                    client.incoming_packet_queue.pop();
                    packet_available = true;
                }
            } // incoming_lk mutex is released here

            if (packet_available) {
                client.last_activity = std::chrono::steady_clock::now(); // Update activity on any packet
                switch (received_packet.flag) {
                    case SYN: { // Should only receive SYN during initial handshake
                        log_message(YELLOW, "Server Handler: Received unexpected SYN from ConnID: " + std::to_string(conn_id) + ". Ignoring.");
                        break;
                    }
                    case ACK: {
                        // Handshake Step 3: Client's Handshake Finished ACK
                        std::string received_payload(received_packet.data, received_packet.length);
                        if (client.state == ClientInfo::HANDSHAKE_SYN_RECEIVED &&
                            received_packet.ack == (client.last_sent_seq + 1) && // Acknowledges server's SYN-ACK
                            received_payload == HANDSHAKE_FINISHED_MSG) { // Contains handshake finished message

                            // Conceptual Key Exchange: Derive shared secret
                            if (!client.client_public_key_for_dh.empty() && !server_private_key_base.empty()) {
                                client.derived_encryption_key = generate_shared_secret(server_private_key_base, client.client_public_key_for_dh);
                                log_message(MAGENTA, "Server Handler: Derived shared encryption key for ConnID " + std::to_string(conn_id) + " (conceptual).");
                            } else {
                                log_message(RED, "Server Handler: Cannot derive key for ConnID " + std::to_string(conn_id) + ". Missing public/private key.");
                            }

                            client.state = ClientInfo::CONNECTED; // Transition to CONNECTED
                            log_message(GREEN, "Server Handler: Handshake Step 3 (Client Handshake Finished ACK) received for ConnID: " + std::to_string(conn_id) + ". State: CONNECTED.");
                            log_message(GREEN, "Server Handler: ConnID " + std::to_string(conn_id) + " is now fully connected and ready for data."); // Debug output

                            // Handshake Step 4: Send Final Server ACK
                            UDPSPacket final_ack_packet;
                            final_ack_packet.flag = ACK;
                            final_ack_packet.conn_id = conn_id;
                            final_ack_packet.seq = (rand() % 1000) + 1; // Server's sequence for this final ACK
                            final_ack_packet.ack = received_packet.seq + 1; // Acknowledging client's Handshake Finished ACK
                            client.last_sent_seq = final_ack_packet.seq;
                            std::vector<char> final_ack_buffer = serialize_packet(final_ack_packet);
                            sendto(server_socket_fd, final_ack_buffer.data(), final_ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent Final ACK (Handshake Step 4) to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(final_ack_packet.seq) +
                                               ", Ack: " + std::to_string(final_ack_packet.ack) + ").");

                        } else {
                            // Process general ACKs for data sent by server to client
                            server_process_ack(client, received_packet.ack); // Use the new server_process_ack
                            log_message(GREEN, "Server Handler: Received ACK from ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(received_packet.seq) +
                                               ", Ack: " + std::to_string(received_packet.ack) + ").");
                        }
                        break;
                    }
                    case DATA: {
                        if (client.state != ClientInfo::CONNECTED) {
                            log_message(YELLOW, "Server Handler: Received DATA from ConnID: " + std::to_string(conn_id) + " but not connected. Ignoring.");
                            break; // Ignore data if not connected
                        }
                        std::lock_guard<std::mutex> reorder_lk(client.reorder_buffer_mutex);
                        // Packet Reordering Buffer logic for server receiving from client
                        if (received_packet.seq == client.next_expected_seq) {
                            // In-order packet
                            if (!client.derived_encryption_key.empty()) {
                                xor_encrypt_decrypt(received_packet.data, received_packet.length, client.derived_encryption_key);
                                log_message(MAGENTA, "Server Handler: Decrypted incoming data from ConnID: " + std::to_string(conn_id) + ".");
                            }
                            client.delivered_messages.push(std::string(received_packet.data, received_packet.length));
                            client.next_expected_seq++;

                            // Deliver buffered packets that are now in order
                            while (client.reorder_buffer.count(client.next_expected_seq)) {
                                UDPSPacket& buffered_packet = client.reorder_buffer[client.next_expected_seq];
                                if (!client.derived_encryption_key.empty()) {
                                    xor_encrypt_decrypt(buffered_packet.data, buffered_packet.length, client.derived_encryption_key);
                                    log_message(MAGENTA, "Server Handler: Decrypted buffered incoming data from ConnID: " + std::to_string(conn_id) + ".");
                                }
                                client.delivered_messages.push(std::string(buffered_packet.data, buffered_packet.length));
                                client.reorder_buffer.erase(client.next_expected_seq);
                                client.next_expected_seq++;
                            }

                            log_message(BLUE, "Server Handler: Received DATA from ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(received_packet.seq) +
                                               ", Ack: " + std::to_string(received_packet.ack) +
                                               ", Len: " + std::to_string(received_packet.length) +
                                               "): " + client.delivered_messages.back()); // Log the last delivered message

                            // Send ACK for received DATA
                            UDPSPacket ack_packet;
                            ack_packet.flag = ACK;
                            ack_packet.conn_id = conn_id;
                            ack_packet.seq = (rand() % 1000) + 1; // Server's sequence for this ACK
                            ack_packet.ack = client.next_expected_seq; // Acknowledge the next expected sequence
                            client.last_sent_seq = ack_packet.seq;
                            std::vector<char> ack_buffer = serialize_packet(ack_packet);
                            sendto(server_socket_fd, ack_buffer.data(), ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent ACK for DATA to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(ack_packet.seq) +
                                               ", Ack: " + std::to_string(ack_packet.ack) + ")");

                        } else if (received_packet.seq > client.next_expected_seq) {
                            // Out-of-order packet, buffer it
                            log_message(YELLOW, "Server Handler: Received out-of-order DATA packet from ConnID: " + std::to_string(conn_id) +
                                                " (Seq: " + std::to_string(received_packet.seq) +
                                                ", Expected: " + std::to_string(client.next_expected_seq) + "). Buffering.");
                            client.reorder_buffer[received_packet.seq] = received_packet;
                            // Still send ACK for the highest in-order sequence received + 1 (cumulative ACK)
                            UDPSPacket ack_packet;
                            ack_packet.flag = ACK;
                            ack_packet.conn_id = conn_id;
                            ack_packet.seq = (rand() % 1000) + 1;
                            ack_packet.ack = client.next_expected_seq; // Still acknowledge what we've received contiguously
                            client.last_sent_seq = ack_packet.seq;
                            std::vector<char> ack_buffer = serialize_packet(ack_packet);
                            sendto(server_socket_fd, ack_buffer.data(), ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent ACK for out-of-order DATA to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(ack_packet.seq) +
                                               ", Ack: " + std::to_string(ack_packet.ack) + ").");
                        } else { // received_packet.seq < client.next_expected_seq (duplicate)
                            log_message(YELLOW, "Server Handler: Received duplicate DATA packet from ConnID: " + std::to_string(conn_id) +
                                                " (Seq: " + std::to_string(received_packet.seq) +
                                                ", Expected ACK: " + std::to_string(client.next_expected_seq) + "). Resending ACK.");
                            // Resend ACK for duplicate
                            UDPSPacket ack_packet;
                            ack_packet.flag = ACK;
                            ack_packet.conn_id = conn_id;
                            ack_packet.seq = client.last_sent_seq;
                            ack_packet.ack = received_packet.seq + 1;
                            std::vector<char> ack_buffer = serialize_packet(ack_packet);
                            sendto(server_socket_fd, ack_buffer.data(), ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                        }
                        break;
                    }
                    case FIN: {
                        log_message(YELLOW, "Server Handler: Received FIN from ConnID: " + std::to_string(conn_id) +
                                           " (Seq: " + std::to_string(received_packet.seq) + "). Sending FIN-ACK.");
                        client.state = ClientInfo::FIN_RECEIVED;

                        // Send FIN-ACK
                        UDPSPacket fin_ack_packet;
                        fin_ack_packet.flag = ACK; // FIN-ACK is an ACK packet
                        fin_ack_packet.conn_id = conn_id;
                        fin_ack_packet.seq = (rand() % 1000) + 1; // Server's sequence for this ACK
                        fin_ack_packet.ack = received_packet.seq + 1; // Acknowledge client's FIN
                        client.last_sent_seq = fin_ack_packet.seq;
                        std::vector<char> fin_ack_buffer = serialize_packet(fin_ack_packet);
                        sendto(server_socket_fd, fin_ack_buffer.data(), fin_ack_buffer.size(), 0,
                               (struct sockaddr*)&client.addr, client.addr_len);
                        log_message(GREEN, "Server Handler: Sent FIN-ACK to ConnID: " + std::to_string(conn_id) +
                                           " (Seq: " + std::to_string(fin_ack_packet.seq) +
                                           ", Ack: " + std::to_string(fin_ack_packet.ack) + ").");
                        // Client will send final ACK, then server will remove client from map in main loop.
                        break;
                    }
                    case PING: {
                        log_message(CYAN, "Server Handler: Received PING from ConnID: " + std::to_string(conn_id) + ". Sending PING-ACK.");
                        UDPSPacket ping_ack_packet;
                        ping_ack_packet.flag = ACK;
                        ping_ack_packet.conn_id = conn_id;
                        ping_ack_packet.seq = (rand() % 1000) + 1;
                        ping_ack_packet.ack = received_packet.seq + 1;
                        client.last_sent_seq = ping_ack_packet.seq;
                        std::vector<char> ping_ack_buffer = serialize_packet(ping_ack_packet);
                        sendto(server_socket_fd, ping_ack_buffer.data(), ping_ack_buffer.size(), 0,
                               (struct sockaddr*)&client.addr, client.addr_len);
                        break;
                    }
                    default: {
                        log_message(YELLOW, "Server Handler: Received unknown packet flag " + std::to_string(received_packet.flag) +
                                           " from ConnID: " + std::to_string(conn_id) + ". Ignoring.");
                        break;
                    }
                }
            }

            // --- Process Outgoing Messages for this client (server sending to client) ---
            std::unique_lock<std::mutex> outgoing_lk(client.outgoing_queue_mutex);
            if (!client.outgoing_message_queue.empty()) {
                std::unique_lock<std::mutex> unacked_lk(client.unacked_mutex);
                
                // BBR-inspired pacing and inflight limit for server's outgoing
                long long time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - client.last_sent_packet_time_us;
                long long pacing_delay_us = (long long)(PAYLOAD_BUFFER_SIZE / client.pacing_rate_bytes_per_ms * 1000.0);

                // Calculate target inflight, ensuring a minimum window for server's outgoing
                double server_target_inflight = (client.delivery_rate_bytes_per_ms * client.min_rtt_us / 1000.0 * client.bbr_current_gain);
                if (server_target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    server_target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
                }

                if (client.bytes_in_flight >= server_target_inflight ||
                    (time_since_last_sent_us < pacing_delay_us && client.pacing_rate_bytes_per_ms > 0.0))
                {
                    log_message(YELLOW, "Server Handler: ConnID " + std::to_string(conn_id) + " Pacing/Inflight limit for outgoing. Waiting...");
                    unacked_lk.unlock(); // Release unacked_mutex before sleeping
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue; // Skip sending for this iteration
                }
                
                std::string message_to_send = client.outgoing_message_queue.front();
                client.outgoing_message_queue.pop();
                unacked_lk.unlock(); // Release unacked_mutex before sending

                if (message_to_send.length() > PAYLOAD_BUFFER_SIZE) {
                    log_message(RED, "Server Handler: Message too long for ConnID " + std::to_string(conn_id) + ". Max " + std::to_string(PAYLOAD_BUFFER_SIZE) + " bytes.");
                } else {
                    UDPSPacket data_packet;
                    data_packet.flag = DATA;
                    data_packet.conn_id = conn_id;
                    data_packet.seq = client.last_sent_seq + 1; // Increment server's sequence for this outgoing packet
                    data_packet.ack = client.next_expected_seq; // Acknowledge client's last received sequence
                    data_packet.length = static_cast<uint16_t>(message_to_send.length());
                    memcpy(data_packet.data, message_to_send.c_str(), message_to_send.length());

                    if (!client.derived_encryption_key.empty()) { // Use derived key for data
                        xor_encrypt_decrypt(data_packet.data, data_packet.length, client.derived_encryption_key);
                        log_message(MAGENTA, "Server Handler: Encrypted outgoing data to ConnID " + std::to_string(conn_id) + ".");
                    }

                    std::vector<char> data_buffer = serialize_packet(data_packet);

                    log_message(BLUE, "Server Handler: Sending DATA to ConnID " + std::to_string(data_packet.conn_id) +
                                       " (Seq: " + std::to_string(data_packet.seq) +
                                       ", Ack: " + std::to_string(data_packet.ack) +
                                       ", Len: " + std::to_string(data_packet.length) + ")");
                    if (sendto(server_socket_fd, data_buffer.data(), data_buffer.size(), 0,
                               (struct sockaddr*)&client.addr, client.addr_len) == UDPS_SOCKET_ERROR) {
                        log_message(RED, "Server Handler: Send DATA to client " + std::to_string(conn_id) + " failed.");
                    } else {
                        // Add to unacked packets and update last sent seq
                        std::lock_guard<std::mutex> unacked_lk_again(client.unacked_mutex);
                        client.unacked_packets[data_packet.seq] = {data_packet, std::chrono::steady_clock::now()};
                        client.bytes_in_flight += data_packet.length;
                        client.last_sent_seq = data_packet.seq;
                        client.last_sent_packet_time_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                    }
                }
            }
            outgoing_lk.unlock(); // Release outgoing_queue_mutex

            // Handle retransmissions for data sent by server to client
            {
                std::lock_guard<std::mutex> unacked_lk(client.unacked_mutex);
                auto now = std::chrono::steady_clock::now();
                for (auto it = client.unacked_packets.begin(); it != client.unacked_packets.end(); ) {
                    auto& packet_info = it->second;
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - packet_info.second).count() > UDPS_TIMEOUT_MS) {
                        log_message(RED, "Server Handler: Retransmitting DATA to ConnID " + std::to_string(conn_id) +
                                            " (Seq: " + std::to_string(packet_info.first.seq) + ") due to timeout.");
                        std::vector<char> data_buffer = serialize_packet(packet_info.first);
                        sendto(server_socket_fd, data_buffer.data(), data_buffer.size(), 0,
                               (struct sockaddr*)&client.addr, client.addr_len);

                        // BBR: Timeout detected, reset to STARTUP (simplified)
                        client.bbr_state = ClientInfo::STARTUP; // Qualified enum
                        client.bbr_current_gain = 2.89;
                        client.min_rtt_us = 0; // Reset min RTT on loss
                        client.delivery_rate_bytes_per_ms = 0.0;
                        log_message(RED, "Server Handler: ConnID " + std::to_string(conn_id) + " Timeout detected. BBR State reset to STARTUP.");

                        packet_info.second = now; // Reset timer for retransmitted packet
                        ++it;
                    } else {
                        ++it;
                    }
                }
            }
            server_update_bbr_state(client); // Update BBR state periodically
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        log_message(CYAN, "Server Handler: Client handler thread for ConnID: " + std::to_string(conn_id) + " stopped.");
    }

    // Dedicated cleanup loop for server
    void cleanup_loop() {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES)); // Check periodically

            std::lock_guard<std::mutex> lock(clients_mutex);
            auto now = std::chrono::steady_clock::now();

            for (auto it = clients.begin(); it != clients.end(); ) {
                auto& client_info = it->second;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - client_info.last_activity).count();

                bool should_cleanup = false;

                if (client_info.state == ClientInfo::FIN_RECEIVED) {
                    // Client has initiated FIN, and its handler thread should be stopping soon.
                    // Clean up once handler is no longer running.
                    if (!client_info.handler_running.load()) {
                        log_message(YELLOW, "Server Cleanup: Removing client (ConnID: " + std::to_string(it->first) + ") after FIN and handler stopped.");
                        should_cleanup = true;
                    }
                } else if (client_info.state == ClientInfo::HANDSHAKE_SYN_RECEIVED) {
                    // Client is in handshake, give it more time for the full handshake to complete.
                    // If no activity after an extended period, assume handshake failed.
                    if (duration > UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES * 5) { // 5x normal timeout for handshake
                        log_message(RED, "Server Cleanup: Removing client (ConnID: " + std::to_string(it->first) + ") due to failed handshake timeout.");
                        client_info.handler_running.store(false); // Signal handler to stop
                        should_cleanup = true;
                    }
                } else if (client_info.state == ClientInfo::CONNECTED) {
                    if (duration > UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES * 60) { // 3x normal timeout for connected clients
                        log_message(YELLOW, "Server Cleanup: Client (ConnID: " + std::to_string(it->first) + ") inactive. Initiating server-side FIN.");
                        // In a real scenario, server would send FIN here.
                        // For this demo, we'll just clean up the internal state and signal handler to stop.
                        client_info.handler_running.store(false); // Signal handler to stop
                        should_cleanup = true;
                    }
                }

                if (should_cleanup) {
                    it = clients.erase(it); // Erase returns iterator to next element
                } else {
                    ++it;
                }
            }
        }
        log_message(CYAN, "Server Cleanup: Cleanup thread stopped.");
    }


public:
    UDPSServer(const std::string& key = "") :
        server_sock(UDPS_INVALID_SOCKET),
        encryption_key_base(key), // This is the base key, will be derived for each client
        server_private_key("server_priv_key_456"), // Example private key for conceptual DH
        running(false),
        next_conn_id(1) { // Start connection IDs from 1
        #ifdef _WIN32
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != 0) {
                log_message(RED, "WSAStartup failed: " + std::to_string(iResult));
                exit(EXIT_FAILURE);
            }
        #endif
        srand(static_cast<unsigned int>(time(0))); // Seed for connection ID generation
    }

    ~UDPSServer() {
        stop();
        if (server_sock != UDPS_INVALID_SOCKET) {
            UDPS_CLOSE_SOCKET(server_sock);
        }
        #ifdef _WIN32
            WSACleanup();
        #endif
    }

    // Start the server on a given port
    bool start(int port) {
        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
        hints.ai_socktype = SOCK_DGRAM; // UDP socket
        hints.ai_flags = AI_PASSIVE; // Fill in my IP for me

        std::string port_str = std::to_string(port);
        int status = getaddrinfo(NULL, port_str.c_str(), &hints, &res);
        if (status != 0) {
            log_message(RED, "Server: Getaddrinfo failed: " + std::string(gai_strerror(status)));
            return false;
        }

        for (p = res; p != NULL; p = p->ai_next) {
            server_sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (server_sock == UDPS_INVALID_SOCKET) {
                log_message(YELLOW, "Server: Failed to create socket for address family " + std::to_string(p->ai_family) + ": " + std::string(strerror(errno)));
                continue;
            }

            // Set socket option for IPv6 dual-stack (allow IPv4 connections on IPv6 socket)
            if (p->ai_family == AF_INET6) {
                int no = 0;
                setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
            }

            if (bind(server_sock, p->ai_addr, p->ai_addrlen) == UDPS_SOCKET_ERROR) {
                // More detailed error logging for bind failure
                #ifdef _WIN32
                    log_message(RED, "Server: Bind failed for " + sockaddr_to_string(reinterpret_cast<sockaddr_storage*>(p->ai_addr), p->ai_addrlen) + ": WSA Error " + std::to_string(WSAGetLastError()));
                #else
                    log_message(RED, "Server: Bind failed for " + sockaddr_to_string(reinterpret_cast<sockaddr_storage*>(p->ai_addr), p->ai_addrlen) + ": " + std::string(strerror(errno)));
                #endif
                UDPS_CLOSE_SOCKET(server_sock);
                server_sock = UDPS_INVALID_SOCKET;
                continue;
            }
            break; // Successfully bound
        }

        if (server_sock == UDPS_INVALID_SOCKET) {
            log_message(RED, "Server: Failed to bind socket after trying all available addresses.");
            freeaddrinfo(res);
            return false;
        }

        // Store server address info
        memcpy(&server_addr_storage, p->ai_addr, p->ai_addrlen);
        server_addr_len = p->ai_addrlen;
        freeaddrinfo(res);

        running.store(true);
        log_message(GREEN, "Server: Listening on port " + std::to_string(port) + " (" + sockaddr_to_string(&server_addr_storage, server_addr_len) + ")");

        cleanup_thread = std::thread(&UDPSServer::cleanup_loop, this); // Start cleanup thread
        return true;
    }

    // Stop the server
    void stop() {
        running.store(false);
        // Signal all client handler threads to stop
        std::unique_lock<std::mutex> lock(clients_mutex); // Changed to unique_lock
        for (auto& pair : clients) {
            pair.second.handler_running.store(false);
            // Notify CVs if any threads are waiting
            pair.second.incoming_queue_cv.notify_all();
            pair.second.outgoing_queue_cv.notify_all();
        }
        lock.unlock(); // Release mutex before joining threads

        if (cleanup_thread.joinable()) {
            cleanup_thread.join(); // Wait for cleanup thread to finish
        }

        // Clients map destructor will join handler threads
        log_message(CYAN, "Server: Shutting down...");
    }

    // Main server listening loop (accepts new connections and dispatches packets)
    void listen_loop() {
        set_socket_timeout(100); // Small timeout to allow checking `running` flag

        while (running.load()) {
            char recv_buf[MAX_PACKET_SIZE];
            sockaddr_storage client_addr_storage; // Use sockaddr_storage for IPv4/IPv6
            socklen_t client_addr_len = sizeof(client_addr_storage);

            int bytes_received = recvfrom(server_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                         (struct sockaddr*)&client_addr_storage, &client_addr_len);

            if (bytes_received == UDPS_SOCKET_ERROR) {
                #ifdef _WIN32
                    if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK) {
                        continue; // No data, continue loop
                    } else {
                        log_message(RED, "Server: Recvfrom error: " + std::to_string(WSAGetLastError()));
                        continue;
                    }
                #else
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        continue; // No data, continue loop
                    } else {
                        perror(RED "Server: Recvfrom error");
                        continue;
                    }
                #endif
            }

            UDPSPacket received_packet = deserialize_packet(recv_buf);
            std::string client_addr_str = sockaddr_to_string(&client_addr_storage, client_addr_len);

            std::lock_guard<std::mutex> lock(clients_mutex); // Protect clients map

            uint16_t current_packet_conn_id = received_packet.conn_id;
            ClientInfo* target_client = nullptr;
            auto client_it = clients.find(current_packet_conn_id); // Use find to look up client

            if (received_packet.flag == SYN) {
                log_message(CYAN, "Server: Received SYN from " + client_addr_str +
                                   " (Seq: " + std::to_string(received_packet.seq) + ")");

                if (client_it != clients.end()) { // This means we received a SYN for an already existing connection (e.g., retransmitted SYN)
                    target_client = &(client_it->second);
                    log_message(YELLOW, "Server: Duplicate SYN from existing client " + client_addr_str +
                                        " (ConnID: " + std::to_string(current_packet_conn_id) + "). Resending SYN-ACK.");
                    // Resend SYN-ACK if it's a duplicate SYN from an already handshaking client
                    UDPSPacket syn_ack_packet;
                    syn_ack_packet.flag = ACK;
                    syn_ack_packet.conn_id = current_packet_conn_id;
                    syn_ack_packet.seq = target_client->last_sent_seq; // Use last sent seq
                    syn_ack_packet.ack = received_packet.seq + 1;
                    // Re-include server's public key (conceptual) in retransmitted SYN-ACK
                    std::string server_public_key_dummy = "server_pub_key_xyz";
                    syn_ack_packet.length = static_cast<uint16_t>(server_public_key_dummy.length());
                    memcpy(syn_ack_packet.data, server_public_key_dummy.c_str(), syn_ack_packet.length);

                    std::vector<char> syn_ack_buffer = serialize_packet(syn_ack_packet);
                    sendto(server_sock, syn_ack_buffer.data(), syn_ack_buffer.size(), 0,
                           (struct sockaddr*)&client_addr_storage, client_addr_len);
                    target_client->last_activity = std::chrono::steady_clock::now();
                } else {
                    // New connection: Generate connection ID and add to map
                    uint16_t new_conn_id = next_conn_id++;
                    // Use emplace with piecewise_construct to correctly construct ClientInfo
                    auto result = clients.emplace(std::piecewise_construct,
                                                  std::forward_as_tuple(new_conn_id),
                                                  std::forward_as_tuple(client_addr_storage, client_addr_len));
                    target_client = &(result.first->second); // Get reference to newly created client
                    target_client->conn_id = new_conn_id; // Set conn_id for the new client
                    target_client->next_expected_seq = received_packet.seq + 1;
                    target_client->state = ClientInfo::HANDSHAKE_SYN_RECEIVED;
                    target_client->client_public_key_for_dh = std::string(received_packet.data, received_packet.length); // Store client's public key

                    // Send SYN-ACK
                    UDPSPacket syn_ack_packet;
                    syn_ack_packet.flag = ACK;
                    syn_ack_packet.conn_id = new_conn_id;
                    syn_ack_packet.seq = (rand() % 1000) + 1; // Server's initial sequence for this connection
                    syn_ack_packet.ack = received_packet.seq + 1; // Acknowledging client's SYN
                    target_client->last_sent_seq = syn_ack_packet.seq;

                    // Conceptual Key Exchange: Include server's public key in SYN-ACK payload
                    std::string server_public_key_dummy = "server_pub_key_xyz";
                    if (server_public_key_dummy.length() > PAYLOAD_BUFFER_SIZE) {
                        log_message(RED, "Server: Dummy public key too long for SYN-ACK payload.");
                        // Handle error or truncate
                    } else {
                        syn_ack_packet.length = static_cast<uint16_t>(server_public_key_dummy.length());
                        memcpy(syn_ack_packet.data, server_public_key_dummy.c_str(), syn_ack_packet.length);
                    }

                    std::vector<char> syn_ack_buffer = serialize_packet(syn_ack_packet);

                    log_message(GREEN, "Server: Sending SYN-ACK to " + client_addr_str +
                                       " (ConnID: " + std::to_string(new_conn_id) +
                                       ", Seq: " + std::to_string(syn_ack_packet.seq) +
                                       ", Ack: " + std::to_string(syn_ack_packet.ack) + ")");
                    sendto(server_sock, syn_ack_buffer.data(), syn_ack_buffer.size(), 0,
                           (struct sockaddr*)&client_addr_storage, client_addr_len);

                    // Start client handler thread
                    target_client->handler_thread = std::thread(&UDPSServer::client_handler_loop, this,
                                                                new_conn_id, server_sock, server_private_key);
                }
            } else if (client_it != clients.end()) {
                // Packet for an existing connection (ACK, DATA, FIN, PING)
                target_client = &(client_it->second);
                // Verify address matches (important for security and correct routing)
                if (memcmp(&target_client->addr, &client_addr_storage, client_addr_len) == 0) {
                    target_client->last_activity = std::chrono::steady_clock::now(); // Update activity

                    // Dispatch packet to the client's handler thread
                    std::lock_guard<std::mutex> incoming_lk(target_client->incoming_queue_mutex);
                    target_client->incoming_packet_queue.push(received_packet);
                    target_client->incoming_queue_cv.notify_one(); // Signal the handler thread
                    log_message(BLUE, "Server: Dispatched packet (Flag: " + std::to_string(received_packet.flag) +
                                       ", ConnID: " + std::to_string(received_packet.conn_id) +
                                       ", Seq: " + std::to_string(received_packet.seq) + ") to handler thread.");
                } else {
                    log_message(YELLOW, "Server: Received packet with known ConnID " + std::to_string(current_packet_conn_id) +
                                        " but from different address (" + client_addr_str + "). Ignoring.");
                }
            } else {
                // Packet for unknown/unconnected ConnID (non-SYN)
                log_message(YELLOW, "Server: Received non-SYN packet for unknown/unconnected ConnID: " + std::to_string(received_packet.conn_id) +
                                    " from " + client_addr_str + ". Ignoring.");
            }
        }
    }

    // Server can queue data to send to a specific client
    bool send_to_client(uint16_t conn_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        // Use find to avoid implicit default construction
        auto it = clients.find(conn_id);
        if (it == clients.end() || it->second.state != ClientInfo::CONNECTED) {
            log_message(RED, "Server: Client with ConnID " + std::to_string(conn_id) + " not found or not connected (State: " +
                                (it == clients.end() ? "N/A" : std::to_string(it->second.state)) + ").");
            return false;
        }

        ClientInfo& client = it->second; // Access via iterator's second element
        std::lock_guard<std::mutex> outgoing_lk(client.outgoing_queue_mutex);
        client.outgoing_message_queue.push(message);
        client.outgoing_queue_cv.notify_one(); // Notify handler thread that there's data to send
        return true;
    }

    // Server can retrieve received messages from a client
    std::string get_client_message(uint16_t conn_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        // Use find to avoid implicit default construction
        auto it = clients.find(conn_id);
        if (it == clients.end() || it->second.state != ClientInfo::CONNECTED) {
            return ""; // No messages if client not found or not connected
        }
        ClientInfo& client = it->second; // Access via iterator's second element
        std::lock_guard<std::mutex> reorder_lk(client.reorder_buffer_mutex);
        if (!client.delivered_messages.empty()) {
            std::string msg = client.delivered_messages.front();
            client.delivered_messages.pop();
            return msg;
        }
        return "";
    }
};

// --- Main Function for CLI Interface / Testing ---
int main(int argc, char* argv[]) {
    // Intro banner shown in terminal
    std::cout << "======================" << std::endl;
    std::cout << "   UDPS Program v1.0  " << std::endl;
    std::cout << "   Mode: Client/Server" << std::endl;
    std::cout << "   Author: Slimey      " << std::endl;
    std::cout << "======================" << std::endl << std::endl;

    // Check if there are enough arguments (at least 3)
    if (argc < 3) {
        // Show usage instructions if arguments are not valid
        std::cerr << "Usage: " << argv[0] << " <client|server> <ip|port> [encryption_key]" << std::endl;
        std::cerr << "  Client: " << argv[0] << " client <server_ip> <server_port> [encryption_key]" << std::endl;
        std::cerr << "  Server: " << argv[0] << " server <listen_port> [encryption_key]" << std::endl;
        return 1; // Exit with error
    }

    std::string mode = argv[1];
    std::string encryption_key_arg = ""; // This is the user-provided key, used as a base
    if (argc >= 4) { // Check if encryption key is provided
        encryption_key_arg = argv[3];
        log_message(MAGENTA, "Using base encryption key: " + encryption_key_arg);
    }

    if (mode == "client") {
        std::string server_ip = argv[2];
        int server_port = std::stoi(argv[3]); // Port is third arg for client
        if (argc == 5) { // Check for encryption key if present
            encryption_key_arg = argv[4];
            log_message(MAGENTA, "Using base encryption key: " + encryption_key_arg);
        }

        UDPSClient client(encryption_key_arg);
        if (!client.connect_to_server(server_ip, server_port)) {
            log_message(RED, "Client: Failed to connect.");
            return 1;
        }

        // Removed client.update_bbr_state() here, as it's now called within send_data/receive_data

        std::string message;
        log_message(GREEN, "Client: Type messages to send. Type 'quit' to exit.");
        while (client.is_connected()) {
            std::cout << WHITE << "You: " << RESET;
            std::getline(std::cin, message);

            if (message == "quit") {
                client.close_connection();
                break;
            }

            if (!message.empty()) {
                client.send_data(message);
            }

            // Check for incoming messages from server
            std::string received_msg = client.receive_data();
            if (!received_msg.empty()) {
                if (received_msg == "[SERVER_CLOSED]") {
                    log_message(RED, "Client: Server closed connection.");
                    break;
                }
                log_message(CYAN, "Server: " + received_msg);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Small delay to prevent busy-waiting
        }
    } else if (mode == "server") {
        int listen_port = std::stoi(argv[2]);
        if (argc == 4) { // Check for encryption key if present
            encryption_key_arg = argv[3];
            log_message(MAGENTA, "Using base encryption key: " + encryption_key_arg);
        }

        UDPSServer server(encryption_key_arg);
        if (!server.start(listen_port)) {
            log_message(RED, "Server: Failed to start.");
            return 1;
        }

        std::thread listen_thread(&UDPSServer::listen_loop, &server);

        log_message(GREEN, "Server: Running. Waiting for clients. Type 'quit' to exit. Type 'send <conn_id> <message>' to echo.");
        std::string cmd_line;
        while (true) {
            std::getline(std::cin, cmd_line);
            if (cmd_line == "quit") {
                server.stop();
                break;
            }

            // Server echo logic for demo
            if (cmd_line.rfind("send ", 0) == 0) { // Starts with "send "
                size_t first_space = cmd_line.find(' ');
                size_t second_space = cmd_line.find(' ', first_space + 1);
                if (first_space != std::string::npos && second_space != std::string::npos) {
                    try {
                        uint16_t target_conn_id = std::stoi(cmd_line.substr(first_space + 1, second_space - first_space - 1));
                        std::string message_to_echo = cmd_line.substr(second_space + 1);
                        server.send_to_client(target_conn_id, message_to_echo);
                    } catch (const std::invalid_argument& e) {
                        log_message(RED, "Server: Invalid connection ID or message format. Usage: send <conn_id> <message>");
                    } catch (const std::out_of_range& e) {
                        log_message(RED, "Server: Connection ID out of range. Usage: send <conn_id> <message>");
                    }
                } else {
                    log_message(RED, "Server: Invalid send command format. Usage: send <conn_id> <message>");
                }
            }

            // Periodically check for messages received by clients and log them
            // In a real application, these would be processed by server logic
            std::lock_guard<std::mutex> lock(server.clients_mutex); // Now accessible
            for (auto& pair : server.clients) { // Now accessible
                uint16_t conn_id = pair.first;
                std::string received_msg = server.get_client_message(conn_id);
                if (!received_msg.empty()) {
                    log_message(CYAN, "Server (from ConnID " + std::to_string(conn_id) + "): " + received_msg);
                    // Example: echo back the message
                    // server.send_to_client(conn_id, "Echo: " + received_msg);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Small delay to prevent busy-waiting
        }

        listen_thread.join(); // Wait for the listening thread to finish
    } else {
        std::cerr << RED << "Invalid mode. Use 'client' or 'server'." << RESET << std::endl;
        return 1;
    }

    return 0;
}
