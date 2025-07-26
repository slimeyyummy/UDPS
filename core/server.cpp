#include "../headers/server.h"

void UDPSServer::set_socket_timeout(int ms) {
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

void UDPSServer::process_ack(std::shared_ptr<ClientInfo> client, uint32_t ack_num) {
    std::lock_guard<std::mutex> lock(client->unacked_mutex);

    auto it = client->unacked_packets.begin();
    while (it != client->unacked_packets.end() && it->first < ack_num) {
        log_message(MAGENTA, "Server: ACKed packet (Seq: " + std::to_string(it->first) + ") for Client " + std::to_string(client->conn_id) + ".");

        auto now = std::chrono::steady_clock::now();
        long long current_rtt_us = std::chrono::duration_cast<std::chrono::microseconds>(now - it->second.second).count();
        if (client->min_rtt_us == 0 || current_rtt_us < client->min_rtt_us) {
            client->min_rtt_us = current_rtt_us;
            log_message(MAGENTA, "Server: New Min RTT for Client " + std::to_string(client->conn_id) + ": " + std::to_string(client->min_rtt_us) + " us");
        }

        client->bytes_acked_since_last_rate_update += it->second.first.length;
        client->bytes_in_flight -= it->second.first.length;

        it = client->unacked_packets.erase(it);
    }
    update_bbr_state(client);
}

void UDPSServer::update_bbr_state(std::shared_ptr<ClientInfo> client) {
    auto now = std::chrono::steady_clock::now();
    long long duration_since_last_update_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - client->last_delivery_rate_update_time).count();

    if (duration_since_last_update_ms > 100) {
        if (client->bytes_acked_since_last_rate_update > 0 && duration_since_last_update_ms > 0) {
            client->delivery_rate_bytes_per_ms = (double)client->bytes_acked_since_last_rate_update / duration_since_last_update_ms;
            log_message(MAGENTA, "Server: Estimated Delivery Rate for Client " + std::to_string(client->conn_id) + ": " + std::to_string(client->delivery_rate_bytes_per_ms) + " B/ms");
        }
        client->bytes_acked_since_last_rate_update = 0;
        client->last_delivery_rate_update_time = now;
    }

    switch (client->bbr_state) {
        case ClientInfo::STARTUP:
            client->bbr_current_gain = 2.89;
            if (client->min_rtt_us > 0 && client->delivery_rate_bytes_per_ms > 0.1 && client->bytes_in_flight > UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
                client->bbr_state = ClientInfo::DRAIN;
                client->bbr_current_gain = 1.0 / 2.89;
                log_message(MAGENTA, "Server: BBR State for Client " + std::to_string(client->conn_id) + ": DRAIN");
            }
            break;
        case ClientInfo::DRAIN:
            if (client->bytes_in_flight <= (client->delivery_rate_bytes_per_ms * client->min_rtt_us / 1000.0 * 1.0) && client->min_rtt_us > 0) {
                client->bbr_state = ClientInfo::PROBE_BW;
                client->bbr_probe_gain_cycle_index = 0;
                client->bbr_current_gain = client->bbr_gains[client->bbr_probe_gain_cycle_index];
                client->last_rtt_probe_time = now;
                log_message(MAGENTA, "Server: BBR State for Client " + std::to_string(client->conn_id) + ": PROBE_BW");
            }
            break;
        case ClientInfo::PROBE_BW:
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client->last_rtt_probe_time).count() > (client->min_rtt_us / 1000.0 * 2)) {
                 client->bbr_probe_gain_cycle_index = (client->bbr_probe_gain_cycle_index + 1) % client->bbr_gains.size();
                 client->bbr_current_gain = client->bbr_gains[client->bbr_probe_gain_cycle_index];
                 client->last_rtt_probe_time = now;
                 log_message(MAGENTA, "Server: BBR State for Client " + std::to_string(client->conn_id) + ": PROBE_BW, New Gain: " + std::to_string(client->bbr_current_gain));
            }
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client->last_rtt_probe_time).count() > client->rtt_probe_interval_ms) {
                client->bbr_state = ClientInfo::PROBE_RTT;
                client->bbr_probe_rtt_start_time = now;
                log_message(MAGENTA, "Server: BBR State for Client " + std::to_string(client->conn_id) + ": PROBE_RTT");
            }
            break;
        case ClientInfo::PROBE_RTT:
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - client->bbr_probe_rtt_start_time).count() > client->rtt_probe_duration_ms) {
                client->bbr_state = ClientInfo::PROBE_BW;
                client->bbr_probe_gain_cycle_index = 0;
                client->bbr_current_gain = client->bbr_gains[client->bbr_probe_gain_cycle_index];
                log_message(MAGENTA, "Server: BBR State for Client " + std::to_string(client->conn_id) + ": PROBE_BW (from PROBE_RTT)");
            }
            break;
    }

    if (client->min_rtt_us > 0 && client->delivery_rate_bytes_per_ms > 0) {
        client->pacing_rate_bytes_per_ms = client->delivery_rate_bytes_per_ms * client->bbr_current_gain;
    } else {
        client->pacing_rate_bytes_per_ms = (double)PAYLOAD_BUFFER_SIZE / (UDPS_TIMEOUT_MS / 2.0);
    }
    if (client->pacing_rate_bytes_per_ms < 0.1) client->pacing_rate_bytes_per_ms = 0.1;
}

void UDPSServer::handle_client_packet(char* buffer, int len, const sockaddr_storage* client_addr, socklen_t client_addr_len) {
    UDPSPacket packet = deserialize_packet(buffer);

    if (packet.flag == SYN) {
        log_message(CYAN, "Server: Received SYN from " + sockaddr_to_string(client_addr, client_addr_len) + ".");

        std::lock_guard<std::mutex> lock(clients_mutex);
        uint16_t new_conn_id = 1;
        while (clients.count(new_conn_id)) new_conn_id++;

        auto new_client = std::make_shared<ClientInfo>();
        memcpy(&new_client->addr, client_addr, client_addr_len);
        new_client->addr_len = client_addr_len;
        new_client->conn_id = new_conn_id;
        new_client->expected_ack_num = packet.seq + 1;
        new_client->last_packet_time = std::chrono::steady_clock::now();

        if (!default_encryption_key.empty()) {
            std::string client_public_key(packet.data, packet.length);
            new_client->encryption_key = generate_shared_secret(server_private_key, client_public_key);
        }

        clients[new_conn_id] = new_client;

        UDPSPacket syn_ack_packet(ACK, new_conn_id, new_client->next_seq_num++, new_client->expected_ack_num);
        std::string server_public_key_dummy = "server_pub_key_xyz"; // Placeholder
        syn_ack_packet.length = static_cast<uint16_t>(server_public_key_dummy.length());
        memcpy(syn_ack_packet.data, server_public_key_dummy.c_str(), syn_ack_packet.length);

        std::vector<char> syn_ack_buffer = serialize_packet(syn_ack_packet);
        sendto(server_sock, syn_ack_buffer.data(), syn_ack_buffer.size(), 0, (struct sockaddr*)client_addr, client_addr_len);
        return;
    }

    std::shared_ptr<ClientInfo> client = nullptr;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(packet.conn_id)) client = clients[packet.conn_id];
    }

    if (!client) return;

    client->last_packet_time = std::chrono::steady_clock::now();

    // Generic packet processing
    switch (packet.flag) {
        case DATA: {
            if (!client->encryption_key.empty()) {
                xor_encrypt_decrypt(packet.data, packet.length, client->encryption_key);
            }
            std::string received_data(packet.data, packet.length);
            log_message(BLUE, "Server: Received DATA from client " + std::to_string(client->conn_id) + ": " + received_data);

            // Echo the data back to the client
            send_to_client(client->conn_id, received_data);
            break;
        }
        case ACK: {
            if (std::string(packet.data, packet.length) == HANDSHAKE_FINISHED_MSG) {
                log_message(GREEN, "Server: Handshake with client " + std::to_string(client->conn_id) + " complete.");
            } else {
                process_ack(client, packet.ack);
            }
            break;
        }
        case FIN: {
            log_message(YELLOW, "Server: Received FIN from client " + std::to_string(client->conn_id) + ".");
            client->is_active.store(false);
            UDPSPacket fin_ack_packet(FIN_ACK, client->conn_id, client->next_seq_num++, packet.seq + 1);
            std::vector<char> fin_ack_buffer = serialize_packet(fin_ack_packet);
            sendto(server_sock, fin_ack_buffer.data(), fin_ack_buffer.size(), 0, (struct sockaddr*)&client->addr, client->addr_len);
            break;
        }
        default: {
            log_message(YELLOW, "Server: Received unhandled packet flag " + std::to_string(packet.flag));
            break;
        }
    }
}

void UDPSServer::start_listening() {
    log_message(GREEN, "Server: Listening for incoming packets...");
    char recv_buf[MAX_PACKET_SIZE];
    sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    while (is_running.load()) {
        int bytes_received = recvfrom(server_sock, recv_buf, MAX_PACKET_SIZE, 0, (struct sockaddr*)&client_addr, &client_addr_len);
        if (bytes_received > 0) {
            handle_client_packet(recv_buf, bytes_received, &client_addr, client_addr_len);
        } else {
            #ifdef _WIN32
                if (WSAGetLastError() != WSAETIMEDOUT && WSAGetLastError() != 0) {
                    log_message(RED, "Server: recvfrom failed with error: " + std::to_string(WSAGetLastError()));
                }
            #else
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    perror(RED "Server: recvfrom failed");
                }
            #endif
        }
    }
}

void UDPSServer::cleanup_inactive_clients() {
    while (is_running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        std::lock_guard<std::mutex> lock(clients_mutex);
        auto it = clients.begin();
        while (it != clients.end()) {
            if (!it->second->is_active.load() || 
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - it->second->last_packet_time).count() > 30) {
                log_message(YELLOW, "Server: Removing inactive/timed-out client " + std::to_string(it->first));
                it = clients.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void UDPSServer::client_handler_thread(std::shared_ptr<ClientInfo> client) {
    log_message(CYAN, "Server: Started handler thread for client " + std::to_string(client->conn_id));
    while (client->is_active.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    log_message(CYAN, "Server: Handler thread for client " + std::to_string(client->conn_id) + " exiting.");
}

UDPSServer::UDPSServer(const std::string& key) : 
    server_sock(UDPS_INVALID_SOCKET), 
    is_running(false), 
    server_private_key("server_priv_key_456"),
    default_encryption_key(key) {
    #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            exit(EXIT_FAILURE);
        }
    #endif
    srand(static_cast<unsigned int>(time(0)));
}

UDPSServer::~UDPSServer() {
    stop();
    #ifdef _WIN32
        WSACleanup();
    #endif
}

bool UDPSServer::start(int port) {
    server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_sock == UDPS_INVALID_SOCKET) {
        log_message(RED, "Server: Socket creation failed.");
        return false;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == UDPS_SOCKET_ERROR) {
        log_message(RED, "Server: Bind failed.");
        UDPS_CLOSE_SOCKET(server_sock);
        return false;
    }

    set_socket_timeout(100); 

    is_running.store(true);
    listener_thread = std::thread(&UDPSServer::start_listening, this);
    cleanup_thread = std::thread(&UDPSServer::cleanup_inactive_clients, this);

    log_message(GREEN, "Server started on port " + std::to_string(port));
    return true;
}

void UDPSServer::stop() {
    is_running.store(false);
    if (listener_thread.joinable()) {
        listener_thread.join();
    }
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
    if (server_sock != UDPS_INVALID_SOCKET) {
        UDPS_CLOSE_SOCKET(server_sock);
        server_sock = UDPS_INVALID_SOCKET;
    }
    log_message(YELLOW, "Server stopped.");
}

bool UDPSServer::send_to_client(uint16_t conn_id, const std::string& message) {
    std::shared_ptr<ClientInfo> client;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(conn_id)) {
            client = clients[conn_id];
        } else {
            log_message(RED, "Server: Attempted to send to unknown client " + std::to_string(conn_id));
            return false;
        }
    }

    if (message.length() > PAYLOAD_BUFFER_SIZE) {
        log_message(RED, "Server: Message too long for client " + std::to_string(conn_id));
        return false;
    }

    std::unique_lock<std::mutex> unacked_lk(client->unacked_mutex);

    long long time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - client->last_sent_packet_time_us;
    long long pacing_delay_us = (long long)(PAYLOAD_BUFFER_SIZE / client->pacing_rate_bytes_per_ms * 1000.0);

    update_bbr_state(client);

    double target_inflight = (client->delivery_rate_bytes_per_ms * client->min_rtt_us / 1000.0 * client->bbr_current_gain);
    if (target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
        target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
    }

    while (client->bytes_in_flight >= target_inflight ||
           (time_since_last_sent_us < pacing_delay_us && client->pacing_rate_bytes_per_ms > 0.0))
    {
        unacked_lk.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        unacked_lk.lock();
        if (!client->is_active.load()) return false;
        time_since_last_sent_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() - client->last_sent_packet_time_us;
    }

    UDPSPacket data_packet;
    data_packet.flag = DATA;
    data_packet.conn_id = conn_id;
    data_packet.seq = client->next_seq_num;
    data_packet.ack = client->expected_ack_num;
    data_packet.length = static_cast<uint16_t>(message.length());
    memcpy(data_packet.data, message.c_str(), message.length());

    if (!client->encryption_key.empty()) {
        xor_encrypt_decrypt(data_packet.data, data_packet.length, client->encryption_key);
    }

    std::vector<char> data_buffer = serialize_packet(data_packet);
    sendto(server_sock, data_buffer.data(), data_buffer.size(), 0, (struct sockaddr*)&client->addr, client->addr_len);

    client->unacked_packets[client->next_seq_num] = {data_packet, std::chrono::steady_clock::now()};
    client->bytes_in_flight += data_packet.length;
    client->next_seq_num++;
    client->last_sent_packet_time_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

    return true;
}

std::string UDPSServer::receive_from_client(uint16_t conn_id) {
    std::shared_ptr<ClientInfo> client;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.count(conn_id)) {
            client = clients[conn_id];
        } else {
            return "";
        }
    }

    std::lock_guard<std::mutex> lock(client->receive_mutex);
    if (!client->received_messages_queue.empty()) {
        std::string msg = client->received_messages_queue.front();
        client->received_messages_queue.pop();
        return msg;
    }
    return "";
}
