#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <algorithm>
#include <utility>
#include <set>
#include <functional>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    #define UDPS_SOCKET SOCKET
    #define UDPS_INVALID_SOCKET INVALID_SOCKET
    #define UDPS_SOCKET_ERROR SOCKET_ERROR
    #define UDPS_CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <errno.h>
    #define UDPS_SOCKET int
    #define UDPS_INVALID_SOCKET -1
    #define UDPS_SOCKET_ERROR -1
    #define UDPS_CLOSE_SOCKET close
#endif

#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"

extern std::mutex log_mutex;
void log_message(const std::string& prefix, const std::string& message, const std::string& color = RESET);

const int MAX_PACKET_SIZE = 512 + sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(uint32_t) + sizeof(uint16_t);
const int PAYLOAD_BUFFER_SIZE = 512;
const int UDPS_TIMEOUT_MS = 200;
const int UDPS_MAX_RETRIES = 5;
const int UDPS_INITIAL_CWND = 1;
const int UDPS_MAX_CWND = 10;

enum UDPSFlag : uint8_t {
    SYN       = 0x01, // Synchronize
    ACK       = 0x02, // Acknowledge
    DATA      = 0x03, // Application data
    FIN       = 0x04, // Finalize connection
    PING      = 0x05, // Ping for keep-alive
    HEARTBEAT = 0x06, // Heartbeat response
    REKEY     = 0x07, // Rekey request
    FIN_ACK   = 0x08  // Finalize Acknowledge
};

#pragma pack(push, 1)
struct UDPSPacket {
    uint8_t flag;
    uint16_t conn_id;
    uint32_t seq;
    uint32_t ack;
    uint16_t length;
    char data[PAYLOAD_BUFFER_SIZE];

    UDPSPacket();
    UDPSPacket(UDPSFlag flag, uint16_t conn_id, uint32_t seq, uint32_t ack);
};
#pragma pack(pop)

const std::string HANDSHAKE_FINISHED_MSG = "UDPS_HANDSHAKE_FINISHED";

std::vector<char> serialize_packet(const UDPSPacket& packet);
UDPSPacket deserialize_packet(const char* buffer);
std::string generate_shared_secret(const std::string& local_private_key, const std::string& remote_public_key);
void xor_encrypt_decrypt(char* data, size_t length, const std::string& key);
std::string sockaddr_to_string(const struct sockaddr_storage* addr, socklen_t addr_len);

#endif // COMMON_H
