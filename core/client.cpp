#include "../headers/client.h"

void UDPSClient::set_socket_timeout(int ms) {
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

void UDPSClient::process_ack(uint32_t ack_num) {
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

void UDPSClient::handle_retransmissions() {
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

void UDPSClient::update_bbr_state() {
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

UDPSClient::UDPSClient(const std::string& key) :
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
    bbr_gains({1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}),
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

UDPSClient::~UDPSClient() {
    if (client_sock != UDPS_INVALID_SOCKET) {
        UDPS_CLOSE_SOCKET(client_sock);
    }
    #ifdef _WIN32
        WSACleanup();
    #endif
}

bool UDPSClient::is_connected() const {
    return connected.load();
}

bool UDPSClient::connect_to_server(const std::string& ip, int port) {
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

bool UDPSClient::send_data(const std::string& message) {
    if (!connected.load()) {
        log_message(RED, "Client: Not connected to server. Call connect() first.");
        return false;
    }
    if (message.length() > PAYLOAD_BUFFER_SIZE) {
        log_message(RED, "Client: Message too long. Max " + std::to_string(PAYLOAD_BUFFER_SIZE) + " bytes.");
        return false;
    }

    std::unique_lock<std::mutex> unacked_lk(unacked_mutex);



    update_bbr_state();

    double target_inflight = (delivery_rate_bytes_per_ms * min_rtt_us / 1000.0 * bbr_current_gain);
    if (target_inflight < UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE) {
        target_inflight = UDPS_INITIAL_CWND * PAYLOAD_BUFFER_SIZE;
    }

    UDPSPacket data_packet;
    data_packet.conn_id = current_conn_id;
    data_packet.seq = next_seq_num;
    data_packet.ack = expected_ack_num;
    data_packet.flag = DATA;
    data_packet.length = static_cast<uint16_t>(message.length());
    memcpy(data_packet.data, message.c_str(), data_packet.length);

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

std::string UDPSClient::receive_data() {
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

void UDPSClient::close_connection() {
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
