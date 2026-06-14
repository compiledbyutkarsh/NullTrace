#pragma once

#include "../packet.hpp"
#include "../types.hpp"
#include <map>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>

namespace NullTrace {

struct FlowKey {
    std::string src_ip;
    std::string dst_ip;
    u16         src_port;
    u16         dst_port;
    Protocol    protocol;

    bool operator==(const FlowKey &other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const {
        size_t h = std::hash<std::string>{}(k.src_ip);
        h ^= std::hash<std::string>{}(k.dst_ip) << 1;
        h ^= std::hash<u16>{}(k.src_port) << 2;
        h ^= std::hash<u16>{}(k.dst_port) << 3;
        return h;
    }
};

struct FlowStats {
    u64         packets;
    u64         bytes;
    Timestamp   first_seen;
    Timestamp   last_seen;
    std::string src_ip;
    std::string dst_ip;
    u16         src_port;
    u16         dst_port;
    Protocol    protocol;

    FlowStats() : packets(0), bytes(0), src_port(0), dst_port(0),
                  protocol(Protocol::UNKNOWN) {}
};

struct NetworkStats {
    u64 total_packets;
    u64 total_bytes;
    u64 tcp_packets;
    u64 udp_packets;
    u64 icmp_packets;
    u64 arp_packets;
    u64 http_packets;
    u64 dns_packets;
    u64 other_packets;

    std::map<std::string, u64> top_talkers;
    std::map<std::string, u64> top_destinations;
    std::map<u16, u64>         top_ports;
    std::map<Protocol, u64>    protocol_dist;

    NetworkStats() : total_packets(0), total_bytes(0),
                     tcp_packets(0), udp_packets(0),
                     icmp_packets(0), arp_packets(0),
                     http_packets(0), dns_packets(0),
                     other_packets(0) {}
};

class PacketAnalyzer {
public:
    PacketAnalyzer();

    void process(const PacketPtr &pkt);
    void reset();

    NetworkStats                                        get_stats() const;
    std::vector<FlowStats>                              get_top_flows(size_t n) const;
    std::vector<std::pair<std::string, u64>>            get_top_talkers(size_t n) const;
    std::vector<std::pair<u16, u64>>                    get_top_ports(size_t n) const;
    std::vector<PacketPtr>                              get_packets() const;
    std::vector<PacketPtr>                              filter_by_protocol(Protocol proto) const;
    std::vector<PacketPtr>                              filter_by_ip(const std::string &ip) const;
    std::vector<PacketPtr>                              filter_by_port(u16 port) const;

private:
    NetworkStats                                                    stats_;
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash>            flows_;
    std::vector<PacketPtr>                                          packets_;
    mutable std::mutex                                              mutex_;

    void update_flow(const PacketPtr &pkt);
    void update_stats(const PacketPtr &pkt);
};

} // namespace NullTrace
