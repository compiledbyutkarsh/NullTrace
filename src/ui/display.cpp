#include "../../include/ui/display.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace NullTrace {

void Display::print_banner() {
    std::cout << Color::BOLD << Color::BCYAN;
    std::cout << "\n";
    std::cout << "  ███╗   ██╗██╗   ██╗██╗     ██╗  ████████╗██████╗  █████╗  ██████╗███████╗\n";
    std::cout << "  ████╗  ██║██║   ██║██║     ██║  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝\n";
    std::cout << "  ██╔██╗ ██║██║   ██║██║     ██║     ██║   ██████╔╝███████║██║     █████╗  \n";
    std::cout << "  ██║╚██╗██║██║   ██║██║     ██║     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  \n";
    std::cout << "  ██║ ╚████║╚██████╔╝███████╗███████╗██║   ██║  ██║██║  ██║╚██████╗███████╗\n";
    std::cout << "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝\n";
    std::cout << Color::RESET;
    std::cout << Color::DIM << "                     Network Packet Analyzer v1.0.0\n";
    std::cout << "                        github.com/compiledbyutkarsh\n";
    std::cout << Color::RESET << "\n";
    print_separator();
}

void Display::print_packet(const PacketPtr &pkt) {
    std::string proto_color = protocol_color(pkt->transport_protocol);
    std::string proto_str   = protocol_to_string(pkt->transport_protocol);

    if (pkt->network_protocol == Protocol::ARP) {
        proto_color = Color::YELLOW;
        proto_str   = "ARP";
    }

    std::cout << Color::DIM << "[" << std::setw(6) << pkt->id << "] " << Color::RESET;
    std::cout << Color::DIM << format_timestamp(pkt->timestamp) << " " << Color::RESET;
    std::cout << proto_color << Color::BOLD << std::setw(6) << proto_str << Color::RESET << " ";

    if (pkt->application_protocol != Protocol::UNKNOWN &&
        pkt->application_protocol != pkt->transport_protocol) {
        std::cout << Color::MAGENTA << "["
                  << protocol_to_string(pkt->application_protocol)
                  << "] " << Color::RESET;
    }

    std::cout << Color::CYAN << std::setw(15) << pkt->src_ip << Color::RESET;
    if (pkt->src_port > 0) {
        std::cout << Color::DIM << ":" << Color::RESET
                  << Color::WHITE << std::setw(5) << pkt->src_port << Color::RESET;
    }

    std::cout << Color::YELLOW << " -> " << Color::RESET;

    std::cout << Color::BGREEN << std::setw(15) << pkt->dst_ip << Color::RESET;
    if (pkt->dst_port > 0) {
        std::cout << Color::DIM << ":" << Color::RESET
                  << Color::WHITE << std::setw(5) << pkt->dst_port << Color::RESET;
    }

    std::cout << Color::DIM << " " << pkt->length << "B" << Color::RESET;

    if (pkt->transport_protocol == Protocol::TCP && pkt->tcp_flags) {
        std::cout << " " << tcp_flags_colored(pkt->tcp_flags);
    }

    if (!pkt->info.empty() && pkt->application_protocol == Protocol::HTTP) {
        std::cout << "\n" << Color::DIM << "         " << pkt->info << Color::RESET;
    }

    std::cout << "\n";
}

void Display::print_stats(const NetworkStats &stats) {
    print_separator();
    std::cout << Color::BOLD << Color::BWHITE << " CAPTURE STATISTICS\n" << Color::RESET;
    print_separator();

    std::cout << Color::CYAN  << " Total Packets : " << Color::BWHITE << stats.total_packets << "\n" << Color::RESET;
    std::cout << Color::CYAN  << " Total Bytes   : " << Color::BWHITE << format_bytes(stats.total_bytes) << "\n" << Color::RESET;

    print_separator();
    std::cout << Color::BOLD << " PROTOCOL BREAKDOWN\n" << Color::RESET;
    print_separator();

    auto print_proto = [&](const std::string &name, u64 count, const char *color) {
        if (count == 0) return;
        double pct = stats.total_packets > 0 ? (count * 100.0 / stats.total_packets) : 0;
        std::cout << color << " " << std::setw(8) << name << " : "
                  << Color::BWHITE << std::setw(8) << count
                  << Color::DIM << " (" << std::fixed << std::setprecision(1) << pct << "%)"
                  << Color::RESET << "\n";
    };

    print_proto("TCP",   stats.tcp_packets,  Color::GREEN);
    print_proto("UDP",   stats.udp_packets,  Color::BLUE);
    print_proto("ICMP",  stats.icmp_packets, Color::YELLOW);
    print_proto("ARP",   stats.arp_packets,  Color::MAGENTA);
    print_proto("HTTP",  stats.http_packets, Color::CYAN);
    print_proto("DNS",   stats.dns_packets,  Color::RED);

    if (!stats.top_talkers.empty()) {
        print_separator();
        std::cout << Color::BOLD << " TOP TALKERS\n" << Color::RESET;
        print_separator();
        int i = 0;
        for (auto &[ip, count] : stats.top_talkers) {
            if (i++ >= 5) break;
            std::cout << Color::CYAN << " " << std::setw(16) << ip
                      << Color::RESET << " : " << Color::BWHITE << count
                      << " packets\n" << Color::RESET;
        }
    }

    if (!stats.top_ports.empty()) {
        print_separator();
        std::cout << Color::BOLD << " TOP PORTS\n" << Color::RESET;
        print_separator();
        int i = 0;
        for (auto &[port, count] : stats.top_ports) {
            if (i++ >= 5) break;
            std::cout << Color::YELLOW << " Port " << std::setw(5) << port
                      << Color::RESET << " : " << Color::BWHITE << count
                      << " packets\n" << Color::RESET;
        }
    }

    print_separator();
}

void Display::print_flows(const std::vector<FlowStats> &flows) {
    print_separator();
    std::cout << Color::BOLD << Color::BWHITE << " TOP NETWORK FLOWS\n" << Color::RESET;
    print_separator();
    std::cout << Color::DIM
              << std::setw(16) << "SRC IP"
              << std::setw(7)  << "SPORT"
              << " -> "
              << std::setw(16) << "DST IP"
              << std::setw(7)  << "DPORT"
              << std::setw(10) << "PACKETS"
              << std::setw(12) << "BYTES"
              << "\n" << Color::RESET;
    print_separator();

    for (auto &flow : flows) {
        std::cout << Color::CYAN   << std::setw(16) << flow.src_ip   << Color::RESET
                  << Color::WHITE  << std::setw(7)  << flow.src_port << Color::RESET
                  << Color::YELLOW << " -> "                          << Color::RESET
                  << Color::BGREEN << std::setw(16) << flow.dst_ip   << Color::RESET
                  << Color::WHITE  << std::setw(7)  << flow.dst_port << Color::RESET
                  << Color::BWHITE << std::setw(10) << flow.packets  << Color::RESET
                  << Color::DIM    << std::setw(12) << format_bytes(flow.bytes) << Color::RESET
                  << "\n";
    }
    print_separator();
}

void Display::print_interfaces(const std::vector<std::string> &ifaces) {
    print_separator();
    std::cout << Color::BOLD << " AVAILABLE INTERFACES\n" << Color::RESET;
    print_separator();
    for (size_t i = 0; i < ifaces.size(); i++) {
        std::cout << Color::CYAN << " [" << i << "] " << Color::BWHITE << ifaces[i] << "\n" << Color::RESET;
    }
    print_separator();
}

void Display::print_hex_dump(const Bytes &data, u32 max_bytes) {
    u32 len = std::min((u32)data.size(), max_bytes);
    std::cout << Color::DIM;
    for (u32 i = 0; i < len; i += 16) {
        std::cout << std::setw(4) << std::setfill('0') << std::hex << i << "  ";
        for (u32 j = 0; j < 16; j++) {
            if (i + j < len) {
                std::cout << std::setw(2) << std::setfill('0')
                          << (int)data[i + j] << " ";
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }
        std::cout << " |";
        for (u32 j = 0; j < 16 && i + j < len; j++) {
            char c = data[i + j];
            std::cout << (c >= 32 && c < 127 ? c : '.');
        }
        std::cout << "|\n";
    }
    std::cout << std::dec << Color::RESET;
}

void Display::print_separator() {
    std::cout << Color::DIM
              << "─────────────────────────────────────────────────────────────\n"
              << Color::RESET;
}

void Display::clear_screen() {
    std::cout << "\033[2J\033[H";
}

std::string Display::protocol_to_string(Protocol proto) {
    switch (proto) {
        case Protocol::TCP:     return "TCP";
        case Protocol::UDP:     return "UDP";
        case Protocol::ICMP:    return "ICMP";
        case Protocol::ARP:     return "ARP";
        case Protocol::HTTP:    return "HTTP";
        case Protocol::HTTPS:   return "HTTPS";
        case Protocol::DNS:     return "DNS";
        case Protocol::FTP:     return "FTP";
        case Protocol::SSH:     return "SSH";
        case Protocol::SMTP:    return "SMTP";
        case Protocol::TELNET:  return "TELNET";
        case Protocol::IP:      return "IP";
        case Protocol::IPV6:    return "IPv6";
        default:                return "???";
    }
}

std::string Display::protocol_color(Protocol proto) {
    switch (proto) {
        case Protocol::TCP:   return Color::GREEN;
        case Protocol::UDP:   return Color::BLUE;
        case Protocol::ICMP:  return Color::YELLOW;
        case Protocol::HTTP:  return Color::CYAN;
        case Protocol::HTTPS: return Color::BCYAN;
        case Protocol::DNS:   return Color::RED;
        case Protocol::SSH:   return Color::MAGENTA;
        default:              return Color::WHITE;
    }
}

std::string Display::format_bytes(u64 bytes) {
    std::ostringstream ss;
    if (bytes < 1024) {
        ss << bytes << "B";
    } else if (bytes < 1024 * 1024) {
        ss << std::fixed << std::setprecision(1) << (bytes / 1024.0) << "KB";
    } else {
        ss << std::fixed << std::setprecision(1) << (bytes / (1024.0 * 1024.0)) << "MB";
    }
    return ss.str();
}

std::string Display::format_timestamp(const Timestamp &ts) {
    auto t  = std::chrono::system_clock::to_time_t(ts);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        ts.time_since_epoch()
    ).count() % 1000;

    std::tm *tm_info = std::localtime(&t);
    std::ostringstream ss;
    ss << std::setw(2) << std::setfill('0') << tm_info->tm_hour << ":"
       << std::setw(2) << std::setfill('0') << tm_info->tm_min  << ":"
       << std::setw(2) << std::setfill('0') << tm_info->tm_sec  << "."
       << std::setw(3) << std::setfill('0') << ms;
    return ss.str();
}

std::string Display::tcp_flags_colored(u8 flags) {
    std::string result;
    if (flags & 0x02) result += std::string(Color::BGREEN)  + "SYN " + Color::RESET;
    if (flags & 0x10) result += std::string(Color::BLUE)    + "ACK " + Color::RESET;
    if (flags & 0x01) result += std::string(Color::YELLOW)  + "FIN " + Color::RESET;
    if (flags & 0x04) result += std::string(Color::BRED)    + "RST " + Color::RESET;
    if (flags & 0x08) result += std::string(Color::MAGENTA) + "PSH " + Color::RESET;
    if (flags & 0x20) result += std::string(Color::RED)     + "URG " + Color::RESET;
    return result;
}

std::string Display::format_mac(const std::string &mac) {
    return mac;
}

} // namespace NullTrace
