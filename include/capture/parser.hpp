#pragma once

#include "../packet.hpp"
#include "../types.hpp"

namespace NullTrace {

class PacketParser {
public:
    static PacketPtr parse(const u8 *data, u32 length, u32 captured_len, Timestamp ts, u64 id);

private:
    static void parse_ethernet(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_ipv4(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_ipv6(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_tcp(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_udp(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_icmp(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_arp(PacketPtr &pkt, const u8 *data, u32 length);
    static void parse_application(PacketPtr &pkt, const u8 *data, u32 length);

    static std::string mac_to_string(const u8 *mac);
    static std::string ipv4_to_string(u32 ip);
    static std::string ipv6_to_string(const u8 *ip);
    static std::string tcp_flags_to_string(u8 flags);
    static Protocol    detect_application_protocol(u16 src_port, u16 dst_port);
};

} // namespace NullTrace
