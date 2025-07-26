#include "headers/server.h"
#include "headers/client.h"
#include <iostream>
#include <thread>
#include <chrono>

void print_banner() {
    log_message(CYAN, "===================================================================", CYAN);
    log_message(CYAN, "    _   _  ____  ____  ____     ", CYAN);
    log_message(CYAN, "   | | | ||  _ \\|  _ \\/ ___|    ", CYAN);
    log_message(CYAN, "   | | | || | | | | | \\___ \\    ", CYAN);
    log_message(CYAN, "   | |_| || |_| | |_| |___) |   ", CYAN);
    log_message(CYAN, "    \\___/ |____/|____/|____/    ", CYAN);
    log_message(CYAN, "                                                                 ", CYAN);
    log_message(CYAN, " reliable UDP networking by slimey (will be adding tls + fingerprinting soon)  ", CYAN);
    log_message(CYAN, "===================================================================", CYAN);
    std::cout << std::endl;
}

void print_usage() {
    std::cerr << "Usage: " << std::endl;
    std::cerr << "  ./udps_app server <port>" << std::endl;
    std::cerr << "  ./udps_app client <ip> <port>" << std::endl;
}

void server_mode(int port) {
    UDPSServer server("my_secret_key");
    if (server.start(port)) {
        log_message(GREEN, "Echo server started. Press Ctrl+C to stop.", GREEN);
        // The server runs in the background, this loop keeps the main thread alive.
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        log_message(RED, "Failed to start server.", RED);
    }
}

void client_mode(const std::string& ip, int port) {
    UDPSClient client("my_secret_key");
    if (!client.connect_to_server(ip, port)) {
        log_message(RED, "Client failed to connect.", RED);
        return;
    }

    log_message(GREEN, "Connected to echo server. Type 'exit' to quit.", GREEN);

    std::atomic<bool> running = {true};

    // Receiver thread
    std::thread receiver_thread([&]() {
        while (running) {
            std::string message = client.receive_data();
            if (!message.empty()) {
                std::cout << "Server echo: " << message << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });

    // Sender loop
    std::string line;
    while (running) {
        std::getline(std::cin, line);
        if (line == "exit" || !std::cin.good()) {
            running = false;
            break;
        }
        if (!line.empty()) {
            client.send_data(line);
        }
    }

    client.close_connection();
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }
    log_message(YELLOW, "Disconnected from server.", YELLOW);
}

int main(int argc, char* argv[]) {
    print_banner();
    if (argc < 3) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];

    if (mode == "server") {
        if (argc != 3) {
            print_usage();
            return 1;
        }
        int port = std::stoi(argv[2]);
        server_mode(port);
    } else if (mode == "client") {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        std::string ip = argv[2];
        int port = std::stoi(argv[3]);
        client_mode(ip, port);
    } else {
        print_usage();
        return 1;
    }

    return 0;
}
