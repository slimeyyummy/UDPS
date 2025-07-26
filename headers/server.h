#ifndef SERVER_H
#define SERVER_H

#include "common.h"

class UDPSServer {
private:
    struct ClientInfo {
        sockaddr_storage addr;
        socklen_t addr_len;
        uint16_t conn_id;
        uint32_t next_seq_num;
        uint32_t expected_ack_num;
        std::string encryption_key;
        std::chrono::steady_clock::time_point last_packet_time;
        std::atomic<bool> is_active;

        enum BBRState { STARTUP, DRAIN, PROBE_BW, PROBE_RTT };
        BBRState bbr_state;
        long long min_rtt_us;
        double delivery_rate_bytes_per_ms;
        std::chrono::steady_clock::time_point last_delivery_rate_update_time;
        size_t bytes_acked_since_last_rate_update;
        size_t bytes_in_flight;
        double pacing_rate_bytes_per_ms;
        double bbr_current_gain;
        std::vector<double> bbr_gains;
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

        ClientInfo() : conn_id(0), next_seq_num(1), expected_ack_num(0), is_active(true), 
                       bbr_state(STARTUP), min_rtt_us(0), delivery_rate_bytes_per_ms(0.0), 
                       bytes_acked_since_last_rate_update(0), bytes_in_flight(0), 
                       pacing_rate_bytes_per_ms(0.0), bbr_current_gain(2.89), 
                       bbr_gains({1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}), 
                       bbr_probe_gain_cycle_index(0), rtt_probe_interval_ms(10000), 
                       rtt_probe_duration_ms(200), last_sent_packet_time_us(0) {}
    };

    UDPS_SOCKET server_sock;
    std::map<uint16_t, std::shared_ptr<ClientInfo>> clients;
    std::mutex clients_mutex;
    std::atomic<bool> is_running;
    std::string server_private_key;
    std::string default_encryption_key;
    std::thread listener_thread;
    std::thread cleanup_thread;

    void set_socket_timeout(int ms);
    void process_ack(std::shared_ptr<ClientInfo> client, uint32_t ack_num);
    void update_bbr_state(std::shared_ptr<ClientInfo> client);
    void handle_client_packet(char* buffer, int len, const sockaddr_storage* client_addr, socklen_t client_addr_len);
    void start_listening();
    void cleanup_inactive_clients();
    void client_handler_thread(std::shared_ptr<ClientInfo> client);

public:
    UDPSServer(const std::string& key = "");
    ~UDPSServer();

    bool start(int port);
    void stop();
    bool send_to_client(uint16_t conn_id, const std::string& message);
    std::string receive_from_client(uint16_t conn_id);
};

#endif // SERVER_H
