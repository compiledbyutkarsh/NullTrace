#pragma once

#include "../packet.hpp"
#include "../analysis/analyzer.hpp"
#include "../types.hpp"
#include <string>
#include <vector>

namespace NullTrace {

namespace Color {
    constexpr const char *RESET   = "\033[0m";
    constexpr const char *BOLD    = "\033[1m";
    constexpr const char *DIM     = "\033[2m";
    constexpr const char *RED     = "\033[31m";
    constexpr const char *GREEN   = "\033[32m";
    constexpr const char *YELLOW  = "\033[33m";
    constexpr const char *BLUE    = "\033[34m";
    constexpr const char *MAGENTA = "\033[35m";
    constexpr const char *CYAN    = "\033[36m";
    constexpr const char *WHITE   = "\033[37m";
    constexpr const char *BRED    = "\033[1;31m";
    constexpr const char *BGREEN  = "\033[1;32m";
    constexpr const char *BYELLOW = "\033[1;33m";
    constexpr const char *BBLUE   = "\033[1;34m";
    constexpr const char *BCYAN   = "\033[1;36m";
    constexpr const char *BWHITE  = "\033[1;37m";
}

class Display {
public:
    static void print_banner();
    static void print_packet(const PacketPtr &pkt);
    static void print_stats(const NetworkStats &stats);
    static void print_flows(const std::vector<FlowStats> &flows);
    static void print_interfaces(const std::vector<std::string> &ifaces);
    static void print_hex_dump(const Bytes &data, u32 max_bytes = 128);
    static void print_separator();
    static void clear_screen();

private:
    static std::string protocol_to_string(Protocol proto);
    static std::string protocol_color(Protocol proto);
    static std::string format_bytes(u64 bytes);
    static std::string format_mac(const std::string &mac);
    static std::string format_timestamp(const Timestamp &ts);
    static std::string tcp_flags_colored(u8 flags);
};

} // namespace NullTrace
