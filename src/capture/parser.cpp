#include "../../include/capture/parser.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace NullTrace {

PacketPtr PacketParser::parse(const u8 *data, u32 length, u32 captured_len, Timestamp ts, u64 id) {
    auto pkt = std::make_shared<Packet>();
    pkt->id               = id;
    pkt->timestamp        = ts;
    pkt->length           = length;
    pkt->captured_length  = captured_len;
    pkt->raw              = Bytes(data, data + captured_len);

    parse_ethernet(pkt, data, captured_len);
    return pkt;
}

void PacketParser::parse_ethernet(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(EthernetHeader)) return;

    auto *eth = reinterpret_cast<const EthernetHeader*>(data);
    pkt->eth_hdr        = eth;
    pkt->link_protocol  = Protocol::ETHERNET;
    pkt->src_mac        = mac_to_string(eth->src_mac);
    pkt->dst_mac        = mac_to_string(eth->dst_mac);

    u16 ether_type = ntohs(eth->ether_type);
    const u8 *next = data + sizeof(EthernetHeader);
    u32 remaining  = length - sizeof(EthernetHeader);

    if (ether_type == ETH_TYPE_IP) {
        parse_ipv4(pkt, next, remaining);
    } else if (ether_type == ETH_TYPE_IPV6) {
        parse_ipv6(pkt, next, remaining);
    } else if (ether_type == ETH_TYPE_ARP) {
        parse_arp(pkt, next, remaining);
    }
}

void PacketParser::parse_ipv4(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(IPv4Header)) return;

    auto *ip = reinterpret_cast<const IPv4Header*>(data);
    pkt->ip4_hdr            = ip;
    pkt->network_protocol   = Protocol::IP;
    pkt->src_ip             = ipv4_to_string(ip->src_ip);
    pkt->dst_ip             = ipv4_to_string(ip->dst_ip);
    pkt->ttl                = ip->ttl;

    u8  ihl      = (ip->version_ihl & 0x0F) * 4;
    const u8 *next = data + ihl;
    u32 remaining  = length - ihl;

    switch (ip->protocol) {
        case PROTO_TCP:  parse_tcp(pkt, next, remaining);  break;
        case PROTO_UDP:  parse_udp(pkt, next, remaining);  break;
        case PROTO_ICMP: parse_icmp(pkt, next, remaining); break;
        default: pkt->transport_protocol = Protocol::UNKNOWN; break;
    }
}

void PacketParser::parse_ipv6(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(IPv6Header)) return;

    auto *ip = reinterpret_cast<const IPv6Header*>(data);
    pkt->ip6_hdr          = ip;
    pkt->network_protocol = Protocol::IPV6;
    pkt->src_ip           = ipv6_to_string(ip->src_ip);
    pkt->dst_ip           = ipv6_to_string(ip->dst_ip);

    const u8 *next = data + sizeof(IPv6Header);
    u32 remaining  = length - sizeof(IPv6Header);

    switch (ip->next_header) {
        case PROTO_TCP:   parse_tcp(pkt, next, remaining);  break;
        case PROTO_UDP:   parse_udp(pkt, next, remaining);  break;
        case PROTO_ICMP6: parse_icmp(pkt, next, remaining); break;
        default: break;
    }
}

void PacketParser::parse_tcp(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(TCPHeader)) return;

    auto *tcp = reinterpret_cast<const TCPHeader*>(data);
    pkt->tcp_hdr              = tcp;
    pkt->transport_protocol   = Protocol::TCP;
    pkt->src_port             = ntohs(tcp->src_port);
    pkt->dst_port             = ntohs(tcp->dst_port);
    pkt->seq_num              = ntohl(tcp->seq_num);
    pkt->ack_num              = ntohl(tcp->ack_num);
    pkt->tcp_flags            = tcp->flags;

    u8 offset     = (tcp->data_offset >> 4) * 4;
    const u8 *next = data + offset;
    u32 remaining  = (length > offset) ? length - offset : 0;

    pkt->application_protocol = detect_application_protocol(pkt->src_port, pkt->dst_port);

    std::string flags = tcp_flags_to_string(tcp->flags);
    pkt->info = pkt->src_ip + ":" + std::to_string(pkt->src_port) +
                " -> " + pkt->dst_ip + ":" + std::to_string(pkt->dst_port) +
                " [" + flags + "] Seq=" + std::to_string(pkt->seq_num);

    if (remaining > 0) {
        parse_application(pkt, next, remaining);
    }
}

void PacketParser::parse_udp(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(UDPHeader)) return;

    auto *udp = reinterpret_cast<const UDPHeader*>(data);
    pkt->udp_hdr              = udp;
    pkt->transport_protocol   = Protocol::UDP;
    pkt->src_port             = ntohs(udp->src_port);
    pkt->dst_port             = ntohs(udp->dst_port);

    pkt->application_protocol = detect_application_protocol(pkt->src_port, pkt->dst_port);
    pkt->info = pkt->src_ip + ":" + std::to_string(pkt->src_port) +
                " -> " + pkt->dst_ip + ":" + std::to_string(pkt->dst_port);
}

void PacketParser::parse_icmp(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(ICMPHeader)) return;

    auto *icmp = reinterpret_cast<const ICMPHeader*>(data);
    pkt->icmp_hdr             = icmp;
    pkt->transport_protocol   = Protocol::ICMP;

    std::string type_str;
    switch (icmp->type) {
        case 0:  type_str = "Echo Reply";   break;
        case 8:  type_str = "Echo Request"; break;
        case 3:  type_str = "Unreachable";  break;
        case 11: type_str = "Time Exceeded"; break;
        default: type_str = "Type " + std::to_string(icmp->type); break;
    }
    pkt->info = pkt->src_ip + " -> " + pkt->dst_ip + " ICMP " + type_str;
}

void PacketParser::parse_arp(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < sizeof(ARPHeader)) return;

    auto *arp = reinterpret_cast<const ARPHeader*>(data);
    pkt->arp_hdr            = arp;
    pkt->network_protocol   = Protocol::ARP;

    u16 op = ntohs(arp->opcode);
    std::string sender_ip = std::to_string(arp->sender_ip[0]) + "." +
                            std::to_string(arp->sender_ip[1]) + "." +
                            std::to_string(arp->sender_ip[2]) + "." +
                            std::to_string(arp->sender_ip[3]);
    std::string target_ip = std::to_string(arp->target_ip[0]) + "." +
                            std::to_string(arp->target_ip[1]) + "." +
                            std::to_string(arp->target_ip[2]) + "." +
                            std::to_string(arp->target_ip[3]);

    pkt->src_ip = sender_ip;
    pkt->dst_ip = target_ip;
    pkt->info   = (op == 1) ? "ARP Request: Who has " + target_ip + "? Tell " + sender_ip
                             : "ARP Reply: " + sender_ip + " is at " + mac_to_string(arp->sender_mac);
}

void PacketParser::parse_application(PacketPtr &pkt, const u8 *data, u32 length) {
    if (length < 4) return;

    if (pkt->application_protocol == Protocol::HTTP) {
        std::string payload(reinterpret_cast<const char*>(data),
                           std::min(length, (u32)128));
        if (payload.find("HTTP/") != std::string::npos ||
            payload.find("GET ")  != std::string::npos ||
            payload.find("POST ") != std::string::npos) {
            size_t end = payload.find("\r\n");
            pkt->info += " | " + payload.substr(0, end != std::string::npos ? end : 64);
        }
    }
}

std::string PacketParser::mac_to_string(const u8 *mac) {
    std::ostringstream ss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
    }
    return ss.str();
}

std::string PacketParser::ipv4_to_string(u32 ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return inet_ntoa(addr);
}

std::string PacketParser::ipv6_to_string(const u8 *ip) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, ip, buf, sizeof(buf));
    return std::string(buf);
}

std::string PacketParser::tcp_flags_to_string(u8 flags) {
    std::string result;
    if (flags & 0x02) result += "SYN ";
    if (flags & 0x10) result += "ACK ";
    if (flags & 0x01) result += "FIN ";
    if (flags & 0x04) result += "RST ";
    if (flags & 0x08) result += "PSH ";
    if (flags & 0x20) result += "URG ";
    if (!result.empty()) result.pop_back();
    return result;
}

Protocol PacketParser::detect_application_protocol(u16 src_port, u16 dst_port) {
    u16 port = (dst_port < src_port) ? dst_port : src_port;
    switch (port) {
        case PORT_HTTP:   return Protocol::HTTP;
        case PORT_HTTPS:  return Protocol::HTTPS;
        case PORT_DNS:    return Protocol::DNS;
        case PORT_FTP:    return Protocol::FTP;
        case PORT_SSH:    return Protocol::SSH;
        case PORT_SMTP:   return Protocol::SMTP;
        case PORT_TELNET: return Protocol::TELNET;
        default:          return Protocol::UNKNOWN;
    }
}

} // namespace NullTrace
