#include "../../include/analysis/analyzer.hpp"
#include <algorithm>
#include <chrono>

namespace NullTrace {

PacketAnalyzer::PacketAnalyzer() {}

void PacketAnalyzer::process(const PacketPtr &pkt) {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.push_back(pkt);
    update_stats(pkt);
    update_flow(pkt);
}

void PacketAnalyzer::reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    packets_.clear();
    flows_.clear();
    stats_ = NetworkStats();
}

void PacketAnalyzer::update_stats(const PacketPtr &pkt) {
    stats_.total_packets++;
    stats_.total_bytes += pkt->length;

    switch (pkt->transport_protocol) {
        case Protocol::TCP:  stats_.tcp_packets++;  break;
        case Protocol::UDP:  stats_.udp_packets++;  break;
        case Protocol::ICMP: stats_.icmp_packets++; break;
        default: break;
    }

    switch (pkt->network_protocol) {
        case Protocol::ARP: stats_.arp_packets++; break;
        default: break;
    }

    switch (pkt->application_protocol) {
        case Protocol::HTTP: stats_.http_packets++; break;
        case Protocol::DNS:  stats_.dns_packets++;  break;
        default: break;
    }

    if (!pkt->src_ip.empty()) {
        stats_.top_talkers[pkt->src_ip]++;
    }
    if (!pkt->dst_ip.empty()) {
        stats_.top_destinations[pkt->dst_ip]++;
    }
    if (pkt->dst_port > 0) {
        stats_.top_ports[pkt->dst_port]++;
    }

    stats_.protocol_dist[pkt->transport_protocol]++;
}

void PacketAnalyzer::update_flow(const PacketPtr &pkt) {
    if (pkt->src_ip.empty() || pkt->dst_ip.empty()) return;

    FlowKey key{
        pkt->src_ip,
        pkt->dst_ip,
        pkt->src_port,
        pkt->dst_port,
        pkt->transport_protocol
    };

    auto &flow = flows_[key];
    if (flow.packets == 0) {
        flow.src_ip    = pkt->src_ip;
        flow.dst_ip    = pkt->dst_ip;
        flow.src_port  = pkt->src_port;
        flow.dst_port  = pkt->dst_port;
        flow.protocol  = pkt->transport_protocol;
        flow.first_seen = pkt->timestamp;
    }

    flow.packets++;
    flow.bytes     += pkt->length;
    flow.last_seen  = pkt->timestamp;
}

NetworkStats PacketAnalyzer::get_stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::vector<FlowStats> PacketAnalyzer::get_top_flows(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FlowStats> flows;
    for (auto &[key, flow] : flows_) {
        flows.push_back(flow);
    }
    std::sort(flows.begin(), flows.end(), [](const FlowStats &a, const FlowStats &b) {
        return a.bytes > b.bytes;
    });
    if (flows.size() > n) flows.resize(n);
    return flows;
}

std::vector<std::pair<std::string, u64>> PacketAnalyzer::get_top_talkers(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<std::string, u64>> talkers(
        stats_.top_talkers.begin(), stats_.top_talkers.end()
    );
    std::sort(talkers.begin(), talkers.end(), [](auto &a, auto &b) {
        return a.second > b.second;
    });
    if (talkers.size() > n) talkers.resize(n);
    return talkers;
}

std::vector<std::pair<u16, u64>> PacketAnalyzer::get_top_ports(size_t n) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::pair<u16, u64>> ports(
        stats_.top_ports.begin(), stats_.top_ports.end()
    );
    std::sort(ports.begin(), ports.end(), [](auto &a, auto &b) {
        return a.second > b.second;
    });
    if (ports.size() > n) ports.resize(n);
    return ports;
}

std::vector<PacketPtr> PacketAnalyzer::get_packets() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return packets_;
}

std::vector<PacketPtr> PacketAnalyzer::filter_by_protocol(Protocol proto) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PacketPtr> result;
    for (auto &pkt : packets_) {
        if (pkt->transport_protocol == proto ||
            pkt->network_protocol   == proto ||
            pkt->application_protocol == proto) {
            result.push_back(pkt);
        }
    }
    return result;
}

std::vector<PacketPtr> PacketAnalyzer::filter_by_ip(const std::string &ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PacketPtr> result;
    for (auto &pkt : packets_) {
        if (pkt->src_ip == ip || pkt->dst_ip == ip) {
            result.push_back(pkt);
        }
    }
    return result;
}

std::vector<PacketPtr> PacketAnalyzer::filter_by_port(u16 port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<PacketPtr> result;
    for (auto &pkt : packets_) {
        if (pkt->src_port == port || pkt->dst_port == port) {
            result.push_back(pkt);
        }
    }
    return result;
}

} // namespace NullTrace
