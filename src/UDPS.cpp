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

std::mutex log_mutex;
void log_message(const std::string& prefix, const std::string& message, const std::string& color = RESET) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << color << prefix << message << RESET << std::endl;
}

const int MAX_PACKET_SIZE = 512 + sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(uint32_t) + sizeof(uint16_t);
const int PAYLOAD_BUFFER_SIZE = 512;
const int UDPS_TIMEOUT_MS = 200; 
const int UDPS_MAX_RETRIES = 5;  
const int UDPS_INITIAL_CWND = 1; 
const int UDPS_MAX_CWND = 10;    

#pragma pack(push, 1) 
struct UDPSPacket {
    uint8_t flag;       
    uint16_t conn_id;   
    uint32_t seq;       
    uint32_t ack;       
    uint16_t length;    
    char data[PAYLOAD_BUFFER_SIZE]; 

    UDPSPacket() : flag(0), conn_id(0), seq(0), ack(0), length(0) {
        memset(data, 0, PAYLOAD_BUFFER_SIZE);
    }
};
#pragma pack(pop) 

enum UDPSFlag : uint8_t {
    SYN       = 0x01,
    ACK       = 0x02,
    DATA      = 0x03,
    FIN       = 0x04,
    PING      = 0x05,
    HEARTBEAT = 0x06,
    REKEY     = 0x07,
    FIN_ACK   = 0x08   
};

const std::string HANDSHAKE_FINISHED_MSG = "UDPS_HANDSHAKE_FINISHED";

std::vector<char> serialize_packet(const UDPSPacket& packet) {
    std::vector<char> buffer(sizeof(UDPSPacket));
    memcpy(buffer.data(), &packet, sizeof(UDPSPacket));
    return buffer;
}

UDPSPacket deserialize_packet(const char* buffer) {
    UDPSPacket packet;
    memcpy(&packet, buffer, sizeof(UDPSPacket));
    return packet;
}

std::string generate_shared_secret(const std::string& local_private_key, const std::string& remote_public_key) {

    std::string combined_key = local_private_key + remote_public_key;
    size_t hash_val = std::hash<std::string>{}(combined_key);
    std::stringstream ss;
    ss << std::hex << std::setw(32) << std::setfill('0') << hash_val;
    return ss.str(); 
}

void xor_encrypt_decrypt(char* data, size_t length, const std::string& key) {
    if (key.empty()) return;
    for (size_t i = 0; i < length; ++i) {
        data[i] = data[i] ^ key[i % key.length()];
    }
}

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

class UDPSClient {
private:
    UDPS_SOCKET client_sock;
    sockaddr_storage server_addr_storage; 
    socklen_t server_addr_len;
    uint16_t current_conn_id;
    uint32_t next_seq_num;      
    uint32_t expected_ack_num;  
    std::string encryption_key; 
    std::string client_private_key; 
    std::atomic<bool> connected; 

    enum BBRState { STARTUP, DRAIN, PROBE_BW, PROBE_RTT };
    BBRState bbr_state;
    long long min_rtt_us; 
    double delivery_rate_bytes_per_ms; 
    std::chrono::steady_clock::time_point last_delivery_rate_update_time;
    size_t bytes_acked_since_last_rate_update;
    size_t bytes_in_flight; 
    double pacing_rate_bytes_per_ms; 
    double bbr_current_gain; 
    std::vector<double> bbr_gains = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}; 
    int bbr_probe_gain_cycle_index;
    std::chrono::steady_clock::time_point last_rtt_probe_time;
    long long rtt_probe_interval_ms; 
    long long rtt_probe_duration_ms; 
    long long last_sent_packet_time_us; 
    std::chrono::steady_clock::time_point bbr_probe_rtt_start_time; 

    std::map<uint32_t, std::pair<UDPSPacket, std::chrono::steady_clock::time_point>> unacked_packets; 
    std::mutex unacked_mutex; 

    std::map<uint32_t, UDPSPacket> reorder_buffer;
    std::queue<std::string> received_messages_queue; 
    std::mutex receive_mutex; 

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

    void process_ack(uint32_t ack_num) {
        std::lock_guard<std::mutex> lock(unacked_mutex);

        auto it = unacked_packets.begin();
        while (it != unacked_packets.end() && it->first < ack_num) {
            log_message(MAGENTA, "Client: ACKed packet (Seq: " + std::to_string(it->first) + "). Removing from unacked queue.");

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
        update_bbr_state(); 
    }

    void handle_retransmissions() {
        std::lock_guard<std::mutex> lock(unacked_mutex);
        auto now = std::chrono::steady_clock::now();
        for (auto it = unacked_packets.begin(); it != unacked_packets.end(); ) {
            auto& packet_info = it->second;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - packet_info.second).count() > UDPS_TIMEOUT_MS) {

                log_message(RED, "Client: Retransmitting DATA (Seq: " + std::to_string(packet_info.first.seq) + ") due to timeout.");
                std::vector<char> data_buffer = serialize_packet(packet_info.first);
                sendto(client_sock, data_buffer.data(), data_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);

                bbr_state = STARTUP;
                bbr_current_gain = 2.89;
                min_rtt_us = 0; 
                delivery_rate_bytes_per_ms = 0.0;
                log_message(RED, "Client: Timeout detected. BBR State reset to STARTUP.");

                packet_info.second = now; 
                ++it;
            } else {
                ++it;
            }
        }
    }

    void update_bbr_state() {
        auto now = std::chrono::steady_clock::now();
        long long duration_since_last_update_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_delivery_rate_update_time).count();

        if (duration_since_last_update_ms > 100) { 
            if (bytes_acked_since_last_rate_update > 0 && duration_since_last_update_ms > 0) {
                delivery_rate_bytes_per_ms = (double)bytes_acked_since_last_rate_update / duration_since_last_update_ms;
                log_message(MAGENTA, "Client: Estimated Delivery Rate: " + std::to_string(delivery_rate_bytes_per_ms) + " B/ms");
            }
            bytes_acked_since_last_rate_update = 0;
            last_delivery_rate_update_time = now;
        }

        switch (bbr_state) {
            case STARTUP:
                bbr_current_gain = 2.89; 

                if (min_rtt_us > 0 && delivery_rate_bytes_per_ms > 0.1 && bytes_in_flight > UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    bbr_state = DRAIN;
                    bbr_current_gain = 1.0 / 2.89; 
                    log_message(MAGENTA, "Client: BBR State: DRAIN");
                }
                break;
            case DRAIN:

                if (bytes_in_flight <= (delivery_rate_bytes_per_ms * min_rtt_us / 1000.0 * 1.0) && min_rtt_us > 0) {
                    bbr_state = PROBE_BW;
                    bbr_probe_gain_cycle_index = 0;
                    bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                    last_rtt_probe_time = now; 
                    log_message(MAGENTA, "Client: BBR State: PROBE_BW");
                }
                break;
            case PROBE_BW:

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rtt_probe_time).count() > (min_rtt_us / 1000.0 * 2)) { 
                     bbr_probe_gain_cycle_index = (bbr_probe_gain_cycle_index + 1) % bbr_gains.size();
                     bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                     last_rtt_probe_time = now;
                     log_message(MAGENTA, "Client: BBR State: PROBE_BW, New Gain: " + std::to_string(bbr_current_gain));
                }

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_rtt_probe_time).count() > rtt_probe_interval_ms) {
                    bbr_state = PROBE_RTT;
                    bbr_probe_rtt_start_time = now; 
                    log_message(MAGENTA, "Client: BBR State: PROBE_RTT");
                }
                break;
            case PROBE_RTT:

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - bbr_probe_rtt_start_time).count() > rtt_probe_duration_ms) {
                    bbr_state = PROBE_BW; 
                    bbr_probe_gain_cycle_index = 0;
                    bbr_current_gain = bbr_gains[bbr_probe_gain_cycle_index];
                    log_message(MAGENTA, "Client: BBR State: PROBE_BW (from PROBE_RTT)");
                }
                break;
        }

        if (min_rtt_us > 0 && delivery_rate_bytes_per_ms > 0) {
            pacing_rate_bytes_per_ms = delivery_rate_bytes_per_ms * bbr_current_gain;
        } else {

            pacing_rate_bytes_per_ms = (double)PAYLOAD_BUFFER_SIZE / (UDPS_TIMEOUT_MS / 2.0); 
        }
        if (pacing_rate_bytes_per_ms < 0.1) pacing_rate_bytes_per_ms = 0.1; 
    }

public:
    UDPSClient(const std::string& key = "") :
        client_sock(UDPS_INVALID_SOCKET),
        current_conn_id(0),
        next_seq_num(1), 
        expected_ack_num(0),
        encryption_key(key),
        client_private_key("client_priv_key_123"), 
        connected(false),

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
        bbr_probe_rtt_start_time(std::chrono::steady_clock::now()) 
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

    bool connect_to_server(const std::string& ip, int port) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; 
        hints.ai_socktype = SOCK_DGRAM; 

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

        memcpy(&server_addr_storage, res->ai_addr, res->ai_addrlen);
        server_addr_len = res->ai_addrlen;
        freeaddrinfo(res); 

        log_message(CYAN, "Client: Attempting to connect to " + sockaddr_to_string(&server_addr_storage, server_addr_len));

        UDPSPacket syn_packet;
        uint32_t syn_packet_seq_sent = next_seq_num; 
        syn_packet.flag = SYN;
        syn_packet.seq = syn_packet_seq_sent;

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
                    if (errno == EWOULDBLOCK || errno == EAGAIN) { 
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

            if (syn_ack_packet.flag == ACK && syn_ack_packet.ack == (syn_packet_seq_sent + 1)) { 
                current_conn_id = syn_ack_packet.conn_id;
                expected_ack_num = syn_ack_packet.seq + 1; 
                log_message(GREEN, "Client: Received SYN-ACK (ConnID: " + std::to_string(current_conn_id) +
                                   ", Seq: " + std::to_string(syn_ack_packet.seq) +
                                   ", Ack: " + std::to_string(syn_ack_packet.ack) + ")");

                std::string server_public_key_from_server(syn_ack_packet.data, syn_ack_packet.length);
                if (!encryption_key.empty()) { 
                    encryption_key = generate_shared_secret(client_private_key, server_public_key_from_server);
                    log_message(MAGENTA, "Client: Derived shared encryption key (conceptual).");
                }

                UDPSPacket handshake_ack_packet;
                handshake_ack_packet.flag = ACK;
                handshake_ack_packet.conn_id = current_conn_id;
                handshake_ack_packet.seq = syn_packet_seq_sent + 1; 
                handshake_ack_packet.ack = expected_ack_num; 

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

                next_seq_num = syn_packet_seq_sent + 2; 
                connected.store(true); 
                log_message(GREEN, "Client: Connection established (Handshake Step 3 complete) with ConnID: " + std::to_string(current_conn_id));

                std::this_thread::sleep_for(std::chrono::milliseconds(50)); 

                return true; 
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

        long long time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - last_sent_packet_time_us;
        long long pacing_delay_us = (long long)(PAYLOAD_BUFFER_SIZE / pacing_rate_bytes_per_ms * 1000.0); 

        update_bbr_state(); 

        double target_inflight = (delivery_rate_bytes_per_ms * min_rtt_us / 1000.0 * bbr_current_gain);
        if (target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
            target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
        }

        while (bytes_in_flight >= target_inflight || 
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
        data_packet.ack = expected_ack_num; 
        data_packet.length = static_cast<uint16_t>(message.length());
        memcpy(data_packet.data, message.c_str(), message.length());

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

        unacked_packets[next_seq_num] = {data_packet, std::chrono::steady_clock::now()};
        bytes_in_flight += data_packet.length;
        next_seq_num++;
        last_sent_packet_time_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        return true;
    }

    std::string receive_data() {
        if (!connected.load()) {
            return "";
        }

        handle_retransmissions();
        update_bbr_state(); 

        set_socket_timeout(10); 
        char recv_buf[MAX_PACKET_SIZE];
        sockaddr_storage temp_addr_storage;
        socklen_t temp_addr_len = sizeof(temp_addr_storage);
        int bytes_received = recvfrom(client_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                     (struct sockaddr*)&temp_addr_storage, &temp_addr_len);

        if (bytes_received == UDPS_SOCKET_ERROR) {
            #ifdef _WIN32
                if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK) {

                    return "";
                } else {
                    log_message(RED, "Client: Recvfrom error during receive: " + std::to_string(WSAGetLastError()));
                    return "";
                }
            #else
                if (errno == EWOULDBLOCK || errno == EAGAIN) {

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
            return ""; 
        }

        if (received_packet.flag == DATA) {
            std::lock_guard<std::mutex> lock(receive_mutex);

            if (received_packet.seq == expected_ack_num) {

                if (!encryption_key.empty()) {
                    xor_encrypt_decrypt(received_packet.data, received_packet.length, encryption_key);
                    log_message(MAGENTA, "Client: Decrypted incoming data.");
                }
                received_messages_queue.push(std::string(received_packet.data, received_packet.length));
                expected_ack_num++;

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

                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = (rand() % 1000) + 1; 
                ack_packet.ack = expected_ack_num;
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
                log_message(GREEN, "Client: Sent ACK for DATA (ConnID: " + std::to_string(ack_packet.conn_id) +
                                   ", Seq: " + std::to_string(ack_packet.seq) +
                                   ", Ack: " + std::to_string(ack_packet.ack) + ")");

            } else if (received_packet.seq > expected_ack_num) {

                log_message(YELLOW, "Client: Received out-of-order DATA packet (Seq: " + std::to_string(received_packet.seq) +
                                    ", Expected: " + std::to_string(expected_ack_num) + "). Buffering.");
                reorder_buffer[received_packet.seq] = received_packet;

                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = next_seq_num++; 
                ack_packet.ack = expected_ack_num; 
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
                log_message(GREEN, "Client: Sent ACK for out-of-order DATA (ConnID: " + std::to_string(ack_packet.conn_id) +
                                   ", Seq: " + std::to_string(ack_packet.seq) +
                                   ", Ack: " + std::to_string(ack_packet.ack) + ").");
            } else { 
                log_message(YELLOW, "Client: Received duplicate DATA packet (Seq: " + std::to_string(received_packet.seq) +
                                    ", Expected ACK: " + std::to_string(expected_ack_num) + "). Sending ACK again.");

                UDPSPacket ack_packet;
                ack_packet.flag = ACK;
                ack_packet.conn_id = current_conn_id;
                ack_packet.seq = next_seq_num;
                ack_packet.ack = received_packet.seq + 1; 
                std::vector<char> ack_buffer = serialize_packet(ack_packet);
                sendto(client_sock, ack_buffer.data(), ack_buffer.size(), 0,
                       (struct sockaddr*)&server_addr_storage, server_addr_len);
            }

            if (!received_messages_queue.empty()) {
                std::string msg = received_messages_queue.front();
                received_messages_queue.pop();
                return msg;
            }
            return "";

        } else if (received_packet.flag == ACK) {

            if (!connected.load()) { 

                if (received_packet.ack == (next_seq_num)) { 
                    log_message(GREEN, "Client: Received final ACK from server (Handshake Step 4 complete).");

                } else {
                    log_message(YELLOW, "Client: Received unexpected ACK during final handshake phase (Ack: " + std::to_string(received_packet.ack) + ", Expected: " + std::to_string(next_seq_num) + ").");
                }
            }
            process_ack(received_packet.ack); 
            log_message(GREEN, "Client: Received ACK (ConnID: " + std::to_string(received_packet.conn_id) +
                               ", Seq: " + std::to_string(received_packet.seq) +
                               ", Ack: " + std::to_string(received_packet.ack) + ").");
            return "";
        } else if (received_packet.flag == FIN) {
            log_message(YELLOW, "Client: Received FIN from server. Initiating graceful shutdown.");
            connected.store(false);

            UDPSPacket fin_ack_packet;
            fin_ack_packet.flag = FIN_ACK;
            fin_ack_packet.conn_id = current_conn_id;
            fin_ack_packet.seq = next_seq_num;
            fin_ack_packet.ack = expected_ack_num; 
            std::vector<char> fin_ack_buffer = serialize_packet(fin_ack_packet);
            sendto(client_sock, fin_ack_buffer.data(), fin_ack_buffer.size(), 0,
                   (struct sockaddr*)&server_addr_storage, server_addr_len);
            log_message(GREEN, "Client: Sent FIN-ACK.");
            close_connection();
            return "[SERVER_CLOSED]"; 
        } else if (received_packet.flag == PING) {
            log_message(CYAN, "Client: Received PING from server (ConnID: " + std::to_string(received_packet.conn_id) + "). Sending PING-ACK.");
            UDPSPacket ping_ack_packet;
            ping_ack_packet.flag = ACK;
            ping_ack_packet.conn_id = current_conn_id;
            ping_ack_packet.seq = next_seq_num;
            ping_ack_packet.ack = expected_ack_num; 
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
                break; 
            }

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

class UDPSServer {
public: 
    UDPS_SOCKET server_sock;
private:
    sockaddr_storage server_addr_storage; 
    socklen_t server_addr_len;
    std::string encryption_key_base; 
    std::string server_private_key; 
    std::atomic<bool> running;
    uint16_t next_conn_id;

    struct ClientInfo {
        uint16_t conn_id; 
        sockaddr_storage addr; 
        socklen_t addr_len;
        uint32_t next_expected_seq; 
        uint32_t last_sent_seq;     
        std::chrono::steady_clock::time_point last_activity;
        enum State { HANDSHAKE_SYN_RECEIVED, CONNECTED, FIN_RECEIVED } state;
        std::string client_public_key_for_dh; 
        std::string derived_encryption_key; 

        std::atomic<bool> handler_running; 
        std::thread handler_thread;       
        std::queue<UDPSPacket> incoming_packet_queue; 
        std::mutex incoming_queue_mutex;              
        std::condition_variable incoming_queue_cv;    

        std::queue<std::string> outgoing_message_queue; 
        std::mutex outgoing_queue_mutex;                
        std::condition_variable outgoing_queue_cv;      

        enum BBRState { STARTUP, DRAIN, PROBE_BW, PROBE_RTT };
        BBRState bbr_state;
        long long min_rtt_us; 
        double delivery_rate_bytes_per_ms; 
        std::chrono::steady_clock::time_point last_delivery_rate_update_time;
        size_t bytes_acked_since_last_rate_update;
        size_t bytes_in_flight; 
        double pacing_rate_bytes_per_ms; 
        double bbr_current_gain; 
        std::vector<double> bbr_gains = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}; 
        int bbr_probe_gain_cycle_index;
        std::chrono::steady_clock::time_point last_rtt_probe_time;
        long long rtt_probe_interval_ms; 
        long long rtt_probe_duration_ms; 
        long long last_sent_packet_time_us; 
        std::chrono::steady_clock::time_point bbr_probe_rtt_start_time; 

        std::map<uint32_t, std::pair<UDPSPacket, std::chrono::steady_clock::time_point>> unacked_packets;
        std::mutex unacked_mutex;

        std::map<uint32_t, UDPSPacket> reorder_buffer;
        std::queue<std::string> delivered_messages; 
        std::mutex reorder_buffer_mutex;

        ClientInfo(sockaddr_storage a, socklen_t al) :
            conn_id(0), 
            addr(a), addr_len(al), next_expected_seq(1), last_sent_seq(0),
            last_activity(std::chrono::steady_clock::now()), state(HANDSHAKE_SYN_RECEIVED),
            handler_running(true), 

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
            bbr_probe_rtt_start_time(std::chrono::steady_clock::now()) 
            {
                last_delivery_rate_update_time = std::chrono::steady_clock::now();
                last_rtt_probe_time = std::chrono::steady_clock::now();
            }

        ~ClientInfo() {
            if (handler_thread.joinable()) { 
                handler_thread.join();
            }
        }
    };

public: 
    std::map<uint16_t, ClientInfo> clients;
    std::mutex clients_mutex; 
    std::thread cleanup_thread; 

private: 

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

    void server_process_ack(ClientInfo& client, uint32_t ack_num) {
        std::lock_guard<std::mutex> lock(client.unacked_mutex);

        auto it = client.unacked_packets.begin();
        while (it != client.unacked_packets.end() && it->first < ack_num) {
            log_message(MAGENTA, "Server Handler: ACKed packet (Seq: " + std::to_string(it->first) + ") for ConnID " + std::to_string(client.conn_id) + ". Removing from unacked queue.");

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
        server_update_bbr_state(client); 
    }

    void server_update_bbr_state(ClientInfo& client) {
        auto now = std::chrono::steady_clock::now();
        long long duration_since_last_update_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_delivery_rate_update_time).count();

        if (duration_since_last_update_ms > 100) { 
            if (client.bytes_acked_since_last_rate_update > 0 && duration_since_last_update_ms > 0) {
                client.delivery_rate_bytes_per_ms = (double)client.bytes_acked_since_last_rate_update / duration_since_last_update_ms;
                log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " Estimated Delivery Rate: " + std::to_string(client.delivery_rate_bytes_per_ms) + " B/ms");
            }
            client.bytes_acked_since_last_rate_update = 0;
            client.last_delivery_rate_update_time = now;
        }

        switch (client.bbr_state) {
            case ClientInfo::STARTUP: 
                client.bbr_current_gain = 2.89; 

                if (client.min_rtt_us > 0 && client.delivery_rate_bytes_per_ms > 0.1 && client.bytes_in_flight > UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    client.bbr_state = ClientInfo::DRAIN; 
                    client.bbr_current_gain = 1.0 / 2.89; 
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: DRAIN");
                }
                break;
            case ClientInfo::DRAIN: 

                if (client.bytes_in_flight <= (client.delivery_rate_bytes_per_ms * client.min_rtt_us / 1000.0 * 1.0) && client.min_rtt_us > 0) {
                    client.bbr_state = ClientInfo::PROBE_BW; 
                    client.bbr_probe_gain_cycle_index = 0;
                    client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                    client.last_rtt_probe_time = now; 
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW");
                }
                break;
            case ClientInfo::PROBE_BW: 

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_rtt_probe_time).count() > (client.min_rtt_us / 1000.0 * 2)) { 
                     client.bbr_probe_gain_cycle_index = (client.bbr_probe_gain_cycle_index + 1) % client.bbr_gains.size();
                     client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                     client.last_rtt_probe_time = now;
                     log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW, New Gain: " + std::to_string(client.bbr_current_gain));
                }

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.last_rtt_probe_time).count() > client.rtt_probe_interval_ms) {
                    client.bbr_state = ClientInfo::PROBE_RTT; 
                    client.bbr_probe_rtt_start_time = now;
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_RTT");
                }
                break;
            case ClientInfo::PROBE_RTT: 

                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client.bbr_probe_rtt_start_time).count() > client.rtt_probe_duration_ms) {
                    client.bbr_state = ClientInfo::PROBE_BW; 
                    client.bbr_probe_gain_cycle_index = 0;
                    client.bbr_current_gain = client.bbr_gains[client.bbr_probe_gain_cycle_index];
                    log_message(MAGENTA, "Server Handler: ConnID " + std::to_string(client.conn_id) + " BBR State: PROBE_BW (from PROBE_RTT)");
                }
                break;
        }

        if (client.min_rtt_us > 0 && client.delivery_rate_bytes_per_ms > 0) {
            client.pacing_rate_bytes_per_ms = client.delivery_rate_bytes_per_ms * client.bbr_current_gain;
        } else {
            client.pacing_rate_bytes_per_ms = (double)PAYLOAD_BUFFER_SIZE / (UDPS_TIMEOUT_MS / 2.0); 
        }
        if (client.pacing_rate_bytes_per_ms < 0.1) client.pacing_rate_bytes_per_ms = 0.1; 
    }

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
        ClientInfo& client = *client_ptr; 
        client.conn_id = conn_id; 

        log_message(CYAN, "Server Handler: Client handler thread started for ConnID: " + std::to_string(conn_id));

        while (client.handler_running.load()) {

            UDPSPacket received_packet;
            bool packet_available = false;
            {
                std::unique_lock<std::mutex> incoming_lk(client.incoming_queue_mutex);

                client.incoming_queue_cv.wait_for(incoming_lk, std::chrono::milliseconds(100),
                                                  [&]{ return !client.incoming_packet_queue.empty() || !client.handler_running.load(); });

                if (!client.incoming_packet_queue.empty()) {
                    received_packet = client.incoming_packet_queue.front();
                    client.incoming_packet_queue.pop();
                    packet_available = true;
                }
            } 

            if (packet_available) {
                client.last_activity = std::chrono::steady_clock::now(); 
                switch (received_packet.flag) {
                    case SYN: { 
                        log_message(YELLOW, "Server Handler: Received unexpected SYN from ConnID: " + std::to_string(conn_id) + ". Ignoring.");
                        break;
                    }
                    case ACK: {

                        std::string received_payload(received_packet.data, received_packet.length);
                        if (client.state == ClientInfo::HANDSHAKE_SYN_RECEIVED &&
                            received_packet.ack == (client.last_sent_seq + 1) && 
                            received_payload == HANDSHAKE_FINISHED_MSG) { 

                            if (!client.client_public_key_for_dh.empty() && !server_private_key_base.empty()) {
                                client.derived_encryption_key = generate_shared_secret(server_private_key_base, client.client_public_key_for_dh);
                                log_message(MAGENTA, "Server Handler: Derived shared encryption key for ConnID " + std::to_string(conn_id) + " (conceptual).");
                            } else {
                                log_message(RED, "Server Handler: Cannot derive key for ConnID " + std::to_string(conn_id) + ". Missing public/private key.");
                            }

                            client.state = ClientInfo::CONNECTED; 
                            log_message(GREEN, "Server Handler: Handshake Step 3 (Client Handshake Finished ACK) received for ConnID: " + std::to_string(conn_id) + ". State: CONNECTED.");
                            log_message(GREEN, "Server Handler: ConnID " + std::to_string(conn_id) + " is now fully connected and ready for data."); 

                            UDPSPacket final_ack_packet;
                            final_ack_packet.flag = ACK;
                            final_ack_packet.conn_id = conn_id;
                            final_ack_packet.seq = (rand() % 1000) + 1; 
                            final_ack_packet.ack = received_packet.seq + 1; 
                            client.last_sent_seq = final_ack_packet.seq;
                            std::vector<char> final_ack_buffer = serialize_packet(final_ack_packet);
                            sendto(server_socket_fd, final_ack_buffer.data(), final_ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent Final ACK (Handshake Step 4) to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(final_ack_packet.seq) +
                                               ", Ack: " + std::to_string(final_ack_packet.ack) + ").");

                        } else {

                            server_process_ack(client, received_packet.ack); 
                            log_message(GREEN, "Server Handler: Received ACK from ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(received_packet.seq) +
                                               ", Ack: " + std::to_string(received_packet.ack) + ").");
                        }
                        break;
                    }
                    case DATA: {
                        if (client.state != ClientInfo::CONNECTED) {
                            log_message(YELLOW, "Server Handler: Received DATA from ConnID: " + std::to_string(conn_id) + " but not connected. Ignoring.");
                            break; 
                        }
                        std::lock_guard<std::mutex> reorder_lk(client.reorder_buffer_mutex);

                        if (received_packet.seq == client.next_expected_seq) {

                            if (!client.derived_encryption_key.empty()) {
                                xor_encrypt_decrypt(received_packet.data, received_packet.length, client.derived_encryption_key);
                                log_message(MAGENTA, "Server Handler: Decrypted incoming data from ConnID: " + std::to_string(conn_id) + ".");
                            }
                            client.delivered_messages.push(std::string(received_packet.data, received_packet.length));
                            client.next_expected_seq++;

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
                                               "): " + client.delivered_messages.back()); 

                            UDPSPacket ack_packet;
                            ack_packet.flag = ACK;
                            ack_packet.conn_id = conn_id;
                            ack_packet.seq = (rand() % 1000) + 1; 
                            ack_packet.ack = client.next_expected_seq; 
                            client.last_sent_seq = ack_packet.seq;
                            std::vector<char> ack_buffer = serialize_packet(ack_packet);
                            sendto(server_socket_fd, ack_buffer.data(), ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent ACK for DATA to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(ack_packet.seq) +
                                               ", Ack: " + std::to_string(ack_packet.ack) + ")");

                        } else if (received_packet.seq > client.next_expected_seq) {

                            log_message(YELLOW, "Server Handler: Received out-of-order DATA packet from ConnID: " + std::to_string(conn_id) +
                                                " (Seq: " + std::to_string(received_packet.seq) +
                                                ", Expected: " + std::to_string(client.next_expected_seq) + "). Buffering.");
                            client.reorder_buffer[received_packet.seq] = received_packet;

                            UDPSPacket ack_packet;
                            ack_packet.flag = ACK;
                            ack_packet.conn_id = conn_id;
                            ack_packet.seq = (rand() % 1000) + 1;
                            ack_packet.ack = client.next_expected_seq; 
                            client.last_sent_seq = ack_packet.seq;
                            std::vector<char> ack_buffer = serialize_packet(ack_packet);
                            sendto(server_socket_fd, ack_buffer.data(), ack_buffer.size(), 0,
                                   (struct sockaddr*)&client.addr, client.addr_len);
                            log_message(GREEN, "Server Handler: Sent ACK for out-of-order DATA to ConnID: " + std::to_string(conn_id) +
                                               " (Seq: " + std::to_string(ack_packet.seq) +
                                               ", Ack: " + std::to_string(ack_packet.ack) + ").");
                        } else { 
                            log_message(YELLOW, "Server Handler: Received duplicate DATA packet from ConnID: " + std::to_string(conn_id) +
                                                " (Seq: " + std::to_string(received_packet.seq) +
                                                ", Expected ACK: " + std::to_string(client.next_expected_seq) + "). Resending ACK.");

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

                        UDPSPacket fin_ack_packet;
                        fin_ack_packet.flag = ACK; 
                        fin_ack_packet.conn_id = conn_id;
                        fin_ack_packet.seq = (rand() % 1000) + 1; 
                        fin_ack_packet.ack = received_packet.seq + 1; 
                        client.last_sent_seq = fin_ack_packet.seq;
                        std::vector<char> fin_ack_buffer = serialize_packet(fin_ack_packet);
                        sendto(server_socket_fd, fin_ack_buffer.data(), fin_ack_buffer.size(), 0,
                               (struct sockaddr*)&client.addr, client.addr_len);
                        log_message(GREEN, "Server Handler: Sent FIN-ACK to ConnID: " + std::to_string(conn_id) +
                                           " (Seq: " + std::to_string(fin_ack_packet.seq) +
                                           ", Ack: " + std::to_string(fin_ack_packet.ack) + ").");

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

            std::unique_lock<std::mutex> outgoing_lk(client.outgoing_queue_mutex);
            if (!client.outgoing_message_queue.empty()) {
                std::unique_lock<std::mutex> unacked_lk(client.unacked_mutex);

                long long time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - client.last_sent_packet_time_us;
                long long pacing_delay_us = (long long)(PAYLOAD_BUFFER_SIZE / client.pacing_rate_bytes_per_ms * 1000.0);

                double server_target_inflight = (client.delivery_rate_bytes_per_ms * client.min_rtt_us / 1000.0 * client.bbr_current_gain);
                if (server_target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                    server_target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
                }

                if (client.bytes_in_flight >= server_target_inflight ||
                    (time_since_last_sent_us < pacing_delay_us && client.pacing_rate_bytes_per_ms > 0.0))
                {
                    log_message(YELLOW, "Server Handler: ConnID " + std::to_string(conn_id) + " Pacing/Inflight limit for outgoing. Waiting...");
                    unacked_lk.unlock(); 
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue; 
                }

                std::string message_to_send = client.outgoing_message_queue.front();
                client.outgoing_message_queue.pop();
                unacked_lk.unlock(); 

                if (message_to_send.length() > PAYLOAD_BUFFER_SIZE) {
                    log_message(RED, "Server Handler: Message too long for ConnID " + std::to_string(conn_id) + ". Max " + std::to_string(PAYLOAD_BUFFER_SIZE) + " bytes.");
                } else {
                    UDPSPacket data_packet;
                    data_packet.flag = DATA;
                    data_packet.conn_id = conn_id;
                    data_packet.seq = client.last_sent_seq + 1; 
                    data_packet.ack = client.next_expected_seq; 
                    data_packet.length = static_cast<uint16_t>(message_to_send.length());
                    memcpy(data_packet.data, message_to_send.c_str(), message_to_send.length());

                    if (!client.derived_encryption_key.empty()) { 
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

                        std::lock_guard<std::mutex> unacked_lk_again(client.unacked_mutex);
                        client.unacked_packets[data_packet.seq] = {data_packet, std::chrono::steady_clock::now()};
                        client.bytes_in_flight += data_packet.length;
                        client.last_sent_seq = data_packet.seq;
                        client.last_sent_packet_time_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                    }
                }
            }
            outgoing_lk.unlock(); 

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

                        client.bbr_state = ClientInfo::STARTUP; 
                        client.bbr_current_gain = 2.89;
                        client.min_rtt_us = 0; 
                        client.delivery_rate_bytes_per_ms = 0.0;
                        log_message(RED, "Server Handler: ConnID " + std::to_string(conn_id) + " Timeout detected. BBR State reset to STARTUP.");

                        packet_info.second = now; 
                        ++it;
                    } else {
                        ++it;
                    }
                }
            }
            server_update_bbr_state(client); 
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        log_message(CYAN, "Server Handler: Client handler thread for ConnID: " + std::to_string(conn_id) + " stopped.");
    }

    void cleanup_loop() {
        while (running.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES)); 

            std::lock_guard<std::mutex> lock(clients_mutex);
            auto now = std::chrono::steady_clock::now();

            for (auto it = clients.begin(); it != clients.end(); ) {
                auto& client_info = it->second;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - client_info.last_activity).count();

                bool should_cleanup = false;

                if (client_info.state == ClientInfo::FIN_RECEIVED) {

                    if (!client_info.handler_running.load()) {
                        log_message(YELLOW, "Server Cleanup: Removing client (ConnID: " + std::to_string(it->first) + ") after FIN and handler stopped.");
                        should_cleanup = true;
                    }
                } else if (client_info.state == ClientInfo::HANDSHAKE_SYN_RECEIVED) {

                    if (duration > UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES * 5) { 
                        log_message(RED, "Server Cleanup: Removing client (ConnID: " + std::to_string(it->first) + ") due to failed handshake timeout.");
                        client_info.handler_running.store(false); 
                        should_cleanup = true;
                    }
                } else if (client_info.state == ClientInfo::CONNECTED) {
                    if (duration > UDPS_TIMEOUT_MS * UDPS_MAX_RETRIES * 60) { 
                        log_message(YELLOW, "Server Cleanup: Client (ConnID: " + std::to_string(it->first) + ") inactive. Initiating server-side FIN.");

                        client_info.handler_running.store(false); 
                        should_cleanup = true;
                    }
                }

                if (should_cleanup) {
                    it = clients.erase(it); 
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
        encryption_key_base(key), 
        server_private_key("server_priv_key_456"), 
        running(false),
        next_conn_id(1) { 
        #ifdef _WIN32
            WSADATA wsaData;
            int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != 0) {
                log_message(RED, "WSAStartup failed: " + std::to_string(iResult));
                exit(EXIT_FAILURE);
            }
        #endif
        srand(static_cast<unsigned int>(time(0))); 
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

    bool start(int port) {
        struct addrinfo hints, *res, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; 
        hints.ai_socktype = SOCK_DGRAM; 
        hints.ai_flags = AI_PASSIVE; 

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

            if (p->ai_family == AF_INET6) {
                int no = 0;
                setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no));
            }

            if (bind(server_sock, p->ai_addr, p->ai_addrlen) == UDPS_SOCKET_ERROR) {

                #ifdef _WIN32
                    log_message(RED, "Server: Bind failed for " + sockaddr_to_string(reinterpret_cast<sockaddr_storage*>(p->ai_addr), p->ai_addrlen) + ": WSA Error " + std::to_string(WSAGetLastError()));
                #else
                    log_message(RED, "Server: Bind failed for " + sockaddr_to_string(reinterpret_cast<sockaddr_storage*>(p->ai_addr), p->ai_addrlen) + ": " + std::string(strerror(errno)));
                #endif
                UDPS_CLOSE_SOCKET(server_sock);
                server_sock = UDPS_INVALID_SOCKET;
                continue;
            }
            break; 
        }

        if (server_sock == UDPS_INVALID_SOCKET) {
            log_message(RED, "Server: Failed to bind socket after trying all available addresses.");
            freeaddrinfo(res);
            return false;
        }

        memcpy(&server_addr_storage, p->ai_addr, p->ai_addrlen);
        server_addr_len = p->ai_addrlen;
        freeaddrinfo(res);

        running.store(true);
        log_message(GREEN, "Server: Listening on port " + std::to_string(port) + " (" + sockaddr_to_string(&server_addr_storage, server_addr_len) + ")");

        cleanup_thread = std::thread(&UDPSServer::cleanup_loop, this); 
        return true;
    }

    void stop() {
        running.store(false);

        std::unique_lock<std::mutex> lock(clients_mutex); 
        for (auto& pair : clients) {
            pair.second.handler_running.store(false);

            pair.second.incoming_queue_cv.notify_all();
            pair.second.outgoing_queue_cv.notify_all();
        }
        lock.unlock(); 

        if (cleanup_thread.joinable()) {
            cleanup_thread.join(); 
        }

        log_message(CYAN, "Server: Shutting down...");
    }

    void listen_loop() {
        set_socket_timeout(100); 

        while (running.load()) {
            char recv_buf[MAX_PACKET_SIZE];
            sockaddr_storage client_addr_storage; 
            socklen_t client_addr_len = sizeof(client_addr_storage);

            int bytes_received = recvfrom(server_sock, recv_buf, MAX_PACKET_SIZE, 0,
                                         (struct sockaddr*)&client_addr_storage, &client_addr_len);

            if (bytes_received == UDPS_SOCKET_ERROR) {
                #ifdef _WIN32
                    if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK) {
                        continue; 
                    } else {
                        log_message(RED, "Server: Recvfrom error: " + std::to_string(WSAGetLastError()));
                        continue;
                    }
                #else
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        continue; 
                    } else {
                        perror(RED "Server: Recvfrom error");
                        continue;
                    }
                #endif
            }

            UDPSPacket received_packet = deserialize_packet(recv_buf);
            std::string client_addr_str = sockaddr_to_string(&client_addr_storage, client_addr_len);

            std::lock_guard<std::mutex> lock(clients_mutex); 

            uint16_t current_packet_conn_id = received_packet.conn_id;
            ClientInfo* target_client = nullptr;
            auto client_it = clients.find(current_packet_conn_id); 

            if (received_packet.flag == SYN) {
                log_message(CYAN, "Server: Received SYN from " + client_addr_str +
                                   " (Seq: " + std::to_string(received_packet.seq) + ")");

                if (client_it != clients.end()) { 
                    target_client = &(client_it->second);
                    log_message(YELLOW, "Server: Duplicate SYN from existing client " + client_addr_str +
                                        " (ConnID: " + std::to_string(current_packet_conn_id) + "). Resending SYN-ACK.");

                    UDPSPacket syn_ack_packet;
                    syn_ack_packet.flag = ACK;
                    syn_ack_packet.conn_id = current_packet_conn_id;
                    syn_ack_packet.seq = target_client->last_sent_seq; 
                    syn_ack_packet.ack = received_packet.seq + 1;

                    std::string server_public_key_dummy = "server_pub_key_xyz";
                    syn_ack_packet.length = static_cast<uint16_t>(server_public_key_dummy.length());
                    memcpy(syn_ack_packet.data, server_public_key_dummy.c_str(), syn_ack_packet.length);

                    std::vector<char> syn_ack_buffer = serialize_packet(syn_ack_packet);
                    sendto(server_sock, syn_ack_buffer.data(), syn_ack_buffer.size(), 0,
                           (struct sockaddr*)&client_addr_storage, client_addr_len);
                    target_client->last_activity = std::chrono::steady_clock::now();
                } else {

                    uint16_t new_conn_id = next_conn_id++;

                    auto result = clients.emplace(std::piecewise_construct,
                                                  std::forward_as_tuple(new_conn_id),
                                                  std::forward_as_tuple(client_addr_storage, client_addr_len));
                    target_client = &(result.first->second); 
                    target_client->conn_id = new_conn_id; 
                    target_client->next_expected_seq = received_packet.seq + 1;
                    target_client->state = ClientInfo::HANDSHAKE_SYN_RECEIVED;
                    target_client->client_public_key_for_dh = std::string(received_packet.data, received_packet.length); 

                    UDPSPacket syn_ack_packet;
                    syn_ack_packet.flag = ACK;
                    syn_ack_packet.conn_id = new_conn_id;
                    syn_ack_packet.seq = (rand() % 1000) + 1; 
                    syn_ack_packet.ack = received_packet.seq + 1; 
                    target_client->last_sent_seq = syn_ack_packet.seq;

                    std::string server_public_key_dummy = "server_pub_key_xyz";
                    if (server_public_key_dummy.length() > PAYLOAD_BUFFER_SIZE) {
                        log_message(RED, "Server: Dummy public key too long for SYN-ACK payload.");

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

                    target_client->handler_thread = std::thread(&UDPSServer::client_handler_loop, this,
                                                                new_conn_id, server_sock, server_private_key);
                }
            } else if (client_it != clients.end()) {

                target_client = &(client_it->second);

                if (memcmp(&target_client->addr, &client_addr_storage, client_addr_len) == 0) {
                    target_client->last_activity = std::chrono::steady_clock::now(); 

                    std::lock_guard<std::mutex> incoming_lk(target_client->incoming_queue_mutex);
                    target_client->incoming_packet_queue.push(received_packet);
                    target_client->incoming_queue_cv.notify_one(); 
                    log_message(BLUE, "Server: Dispatched packet (Flag: " + std::to_string(received_packet.flag) +
                                       ", ConnID: " + std::to_string(received_packet.conn_id) +
                                       ", Seq: " + std::to_string(received_packet.seq) + ") to handler thread.");
                } else {
                    log_message(YELLOW, "Server: Received packet with known ConnID " + std::to_string(current_packet_conn_id) +
                                        " but from different address (" + client_addr_str + "). Ignoring.");
                }
            } else {

                log_message(YELLOW, "Server: Received non-SYN packet for unknown/unconnected ConnID: " + std::to_string(received_packet.conn_id) +
                                    " from " + client_addr_str + ". Ignoring.");
            }
        }
    }

    bool send_to_client(uint16_t conn_id, const std::string& message) {
        std::lock_guard<std::mutex> lock(clients_mutex);

        auto it = clients.find(conn_id);
        if (it == clients.end() || it->second.state != ClientInfo::CONNECTED) {
            log_message(RED, "Server: Client with ConnID " + std::to_string(conn_id) + " not found or not connected (State: " +
                                (it == clients.end() ? "N/A" : std::to_string(it->second.state)) + ").");
            return false;
        }

        ClientInfo& client = it->second; 
        std::lock_guard<std::mutex> outgoing_lk(client.outgoing_queue_mutex);
        client.outgoing_message_queue.push(message);
        client.outgoing_queue_cv.notify_one(); 
        return true;
    }

    std::string get_client_message(uint16_t conn_id) {
        std::lock_guard<std::mutex> lock(clients_mutex);

        auto it = clients.find(conn_id);
        if (it == clients.end() || it->second.state != ClientInfo::CONNECTED) {
            return ""; 
        }
        ClientInfo& client = it->second; 
        std::lock_guard<std::mutex> reorder_lk(client.reorder_buffer_mutex);
        if (!client.delivered_messages.empty()) {
            std::string msg = client.delivered_messages.front();
            client.delivered_messages.pop();
            return msg;
        }
        return "";
    }
};

int main(int argc, char* argv[]) {

    std::cout << "======================" << std::endl;
    std::cout << "   UDPS Program v1.0  " << std::endl;
    std::cout << "   Mode: Client/Server" << std::endl;
    std::cout << "   Author: Slimey      " << std::endl;
    std::cout << "======================" << std::endl << std::endl;

    if (argc < 3) {

        std::cerr << "Usage: " << argv[0] << " <client|server> <ip|port> [encryption_key]" << std::endl;
        std::cerr << "  Client: " << argv[0] << " client <server_ip> <server_port> [encryption_key]" << std::endl;
        std::cerr << "  Server: " << argv[0] << " server <listen_port> [encryption_key]" << std::endl;
        return 1; 
    }

    std::string mode = argv[1];
    std::string encryption_key_arg = ""; 
    if (argc >= 4) { 
        encryption_key_arg = argv[3];
        log_message(MAGENTA, "Using base encryption key: " + encryption_key_arg);
    }

    if (mode == "client") {
        std::string server_ip = argv[2];
        int server_port = std::stoi(argv[3]); 
        if (argc == 5) { 
            encryption_key_arg = argv[4];
            log_message(MAGENTA, "Using base encryption key: " + encryption_key_arg);
        }

        UDPSClient client(encryption_key_arg);
        if (!client.connect_to_server(server_ip, server_port)) {
            log_message(RED, "Client: Failed to connect.");
            return 1;
        }

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

            std::string received_msg = client.receive_data();
            if (!received_msg.empty()) {
                if (received_msg == "[SERVER_CLOSED]") {
                    log_message(RED, "Client: Server closed connection.");
                    break;
                }
                log_message(CYAN, "Server: " + received_msg);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10)); 
        }
    } else if (mode == "server") {
        int listen_port = std::stoi(argv[2]);
        if (argc == 4) { 
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

            if (cmd_line.rfind("send ", 0) == 0) { 
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

            std::lock_guard<std::mutex> lock(server.clients_mutex); 
            for (auto& pair : server.clients) { 
                uint16_t conn_id = pair.first;
                std::string received_msg = server.get_client_message(conn_id);
                if (!received_msg.empty()) {
                    log_message(CYAN, "Server (from ConnID " + std::to_string(conn_id) + "): " + received_msg);

                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); 
        }

        listen_thread.join(); 
    } else {
        std::cerr << RED << "Invalid mode. Use 'client' or 'server'." << RESET << std::endl;
        return 1;
    }

    return 0;
}
