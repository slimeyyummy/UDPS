#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"

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

    void set_socket_timeout(int ms);
    void process_ack(uint32_t ack_num);
    void handle_retransmissions();
    void update_bbr_state();

public:
    UDPSClient(const std::string& key = "");
    ~UDPSClient();

    bool is_connected() const;
    bool connect_to_server(const std::string& ip, int port);
    bool send_data(const std::string& message);
    std::string receive_data();
    void close_connection();
};

#endif // CLIENT_H
