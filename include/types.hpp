#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <array>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using Bytes     = std::vector<u8>;
using Timestamp = std::chrono::time_point<std::chrono::system_clock>;

namespace NullTrace {

constexpr u16 ETH_TYPE_IP   = 0x0800;
constexpr u16 ETH_TYPE_IPV6 = 0x86DD;
constexpr u16 ETH_TYPE_ARP  = 0x0806;

constexpr u8 PROTO_ICMP  = 1;
constexpr u8 PROTO_TCP   = 6;
constexpr u8 PROTO_UDP   = 17;
constexpr u8 PROTO_ICMP6 = 58;

constexpr u16 PORT_HTTP   = 80;
constexpr u16 PORT_HTTPS  = 443;
constexpr u16 PORT_DNS    = 53;
constexpr u16 PORT_FTP    = 21;
constexpr u16 PORT_SSH    = 22;
constexpr u16 PORT_SMTP   = 25;
constexpr u16 PORT_TELNET = 23;

enum class Protocol {
    UNKNOWN,
    ETHERNET,
    ARP,
    IP,
    IPV6,
    ICMP,
    TCP,
    UDP,
    HTTP,
    HTTPS,
    DNS,
    FTP,
    SSH,
    SMTP,
    TELNET
};

enum class Direction {
    INBOUND,
    OUTBOUND,
    UNKNOWN
};

} // namespace NullTrace
