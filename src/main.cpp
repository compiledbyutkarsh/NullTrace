#include "../include/capture/capture.hpp"
#include "../include/analysis/analyzer.hpp"
#include "../include/ui/display.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>
#include <string>
#include <cstring>
#include <iomanip>

using namespace NullTrace;

static std::atomic<bool>  g_running{true};
static PacketAnalyzer     g_analyzer;
static CaptureEngine     *g_engine = nullptr;

static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
    if (g_engine) g_engine->stop();
}

static void print_usage(const char *prog) {
    std::cout << "\n";
    std::cout << Color::BOLD << " Usage: " << Color::RESET << prog << " [options]\n\n";
    std::cout << Color::CYAN << " Options:\n" << Color::RESET;
    std::cout << "   -i <interface>   Network interface to capture on\n";
    std::cout << "   -f <filter>      BPF filter expression (e.g. 'tcp port 80')\n";
    std::cout << "   -c <count>       Stop after capturing N packets\n";
    std::cout << "   -s               Show stats on exit\n";
    std::cout << "   -l               List available interfaces\n";
    std::cout << "   -h               Show this help\n\n";
    std::cout << Color::DIM << " Examples:\n";
    std::cout << "   sudo " << prog << " -i en0\n";
    std::cout << "   sudo " << prog << " -i en0 -f 'tcp port 443'\n";
    std::cout << "   sudo " << prog << " -i en0 -f 'host 8.8.8.8' -c 100\n\n" << Color::RESET;
}

int main(int argc, char *argv[]) {
    Display::print_banner();

    std::string interface;
    std::string filter;
    int         count      = -1;
    bool        show_stats = false;
    bool        list_ifaces = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[++i];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            filter = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            count = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0) {
            show_stats = true;
        } else if (strcmp(argv[i], "-l") == 0) {
            list_ifaces = true;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    auto ifaces = CaptureEngine::list_interfaces();

    if (list_ifaces) {
        Display::print_interfaces(ifaces);
        return 0;
    }

    if (interface.empty()) {
        if (!ifaces.empty()) {
            interface = ifaces[0];
        } else {
            interface = CaptureEngine::get_default_interface();
        }
    }

    std::cout << Color::BOLD << " Interface : " << Color::BCYAN  << interface << Color::RESET << "\n";
    std::cout << Color::BOLD << " Filter    : " << Color::YELLOW << (filter.empty() ? "none" : filter) << Color::RESET << "\n";
    std::cout << Color::BOLD << " Count     : " << Color::WHITE  << (count < 0 ? "unlimited" : std::to_string(count)) << Color::RESET << "\n\n";

    Display::print_separator();
    std::cout << Color::DIM
              << std::setw(8)  << "ID"
              << std::setw(13) << "TIME"
              << std::setw(7)  << "PROTO"
              << "  "
              << std::setw(15) << "SRC"
              << std::setw(7)  << "SPORT"
              << "    "
              << std::setw(15) << "DST"
              << std::setw(7)  << "DPORT"
              << std::setw(8)  << "LEN"
              << "\n" << Color::RESET;
    Display::print_separator();

    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    CaptureConfig config;
    config.interface   = interface;
    config.filter      = filter;
    config.promiscuous = true;
    config.snaplen     = 65535;
    config.timeout_ms  = 100;

    CaptureEngine engine(config);
    g_engine = &engine;

    u64 captured = 0;

    engine.set_packet_callback([&](PacketPtr pkt) {
        if (!g_running) return;

        g_analyzer.process(pkt);
        Display::print_packet(pkt);

        if (count > 0 && ++captured >= (u64)count) {
            g_running = false;
            engine.stop();
        }
    });

    if (!engine.start()) {
        std::cerr << Color::BRED << "\n [ERR] Failed to start capture. Try running with sudo.\n" << Color::RESET;
        return 1;
    }

    std::cout << Color::BGREEN << " [*] Capture started. Press Ctrl+C to stop.\n\n" << Color::RESET;

    while (g_running && engine.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    engine.stop();

    auto stats = g_analyzer.get_stats();
    std::cout << "\n";

    if (show_stats || stats.total_packets > 0) {
        Display::print_stats(stats);
    }

    auto flows = g_analyzer.get_top_flows(10);
    if (!flows.empty()) {
        Display::print_flows(flows);
    }

    std::cout << Color::BGREEN << "\n [*] Capture complete. "
              << stats.total_packets << " packets captured.\n\n" << Color::RESET;

    return 0;
}
