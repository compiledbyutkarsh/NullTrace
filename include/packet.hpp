#pragma once

#include "types.hpp"
#include <string>
#include <vector>
#include <memory>

namespace NullTrace {

struct EthernetHeader {
    u8  dst_mac[6];
    u8  src_mac[6];
    u16 ether_type;
} __attribute__((packed));

struct IPv4Header {
    u8  version_ihl;
    u8  tos;
    u16 total_length;
    u16 identification;
    u16 flags_fragment;
    u8  ttl;
    u8  protocol;
    u16 checksum;
    u32 src_ip;
    u32 dst_ip;
} __attribute__((packed));

struct IPv6Header {
    u32 version_tc_flow;
    u16 payload_length;
    u8  next_header;
    u8  hop_limit;
    u8  src_ip[16];
    u8  dst_ip[16];
} __attribute__((packed));

struct TCPHeader {
    u16 src_port;
    u16 dst_port;
    u32 seq_num;
    u32 ack_num;
    u8  data_offset;
    u8  flags;
    u16 window_size;
    u16 checksum;
    u16 urgent_ptr;
} __attribute__((packed));

struct UDPHeader {
    u16 src_port;
    u16 dst_port;
    u16 length;
    u16 checksum;
} __attribute__((packed));

struct ICMPHeader {
    u8  type;
    u8  code;
    u16 checksum;
    u32 rest;
} __attribute__((packed));

struct ARPHeader {
    u16 hw_type;
    u16 proto_type;
    u8  hw_size;
    u8  proto_size;
    u16 opcode;
    u8  sender_mac[6];
    u8  sender_ip[4];
    u8  target_mac[6];
    u8  target_ip[4];
} __attribute__((packed));

struct Packet {
    u64       id;
    Timestamp timestamp;
    Bytes     raw;
    u32       length;
    u32       captured_length;

    Protocol  link_protocol;
    Protocol  network_protocol;
    Protocol  transport_protocol;
    Protocol  application_protocol;

    std::string src_ip;
    std::string dst_ip;
    std::string src_mac;
    std::string dst_mac;
    u16         src_port;
    u16         dst_port;

    u8  ttl;
    u8  tcp_flags;
    u32 seq_num;
    u32 ack_num;

    std::string info;
    Direction   direction;

    const EthernetHeader *eth_hdr  = nullptr;
    const IPv4Header     *ip4_hdr  = nullptr;
    const IPv6Header     *ip6_hdr  = nullptr;
    const TCPHeader      *tcp_hdr  = nullptr;
    const UDPHeader      *udp_hdr  = nullptr;
    const ICMPHeader     *icmp_hdr = nullptr;
    const ARPHeader      *arp_hdr  = nullptr;

    Packet() : id(0), length(0), captured_length(0),
               link_protocol(Protocol::UNKNOWN),
               network_protocol(Protocol::UNKNOWN),
               transport_protocol(Protocol::UNKNOWN),
               application_protocol(Protocol::UNKNOWN),
               src_port(0), dst_port(0),
               ttl(0), tcp_flags(0),
               seq_num(0), ack_num(0),
               direction(Direction::UNKNOWN) {}
};

using PacketPtr = std::shared_ptr<Packet>;

} // namespace NullTrace
