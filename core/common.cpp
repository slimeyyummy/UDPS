#include "../headers/common.h"

std::mutex log_mutex;

UDPSPacket::UDPSPacket() : flag(DATA), conn_id(0), seq(0), ack(0), length(0) {
    memset(data, 0, PAYLOAD_BUFFER_SIZE);
}

UDPSPacket::UDPSPacket(UDPSFlag flag, uint16_t conn_id, uint32_t seq, uint32_t ack)
    : flag(flag), conn_id(conn_id), seq(seq), ack(ack), length(0) {
    memset(data, 0, PAYLOAD_BUFFER_SIZE);
}

void log_message(const std::string& prefix, const std::string& message, const std::string& color) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::cout << color << prefix << message << RESET << std::endl;
}

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



std::string sockaddr_to_string(const struct sockaddr_storage* sa, socklen_t salen) {
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
