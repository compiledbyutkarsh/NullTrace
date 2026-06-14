#pragma once

#include "../packet.hpp"
#include "../types.hpp"
#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <functional>

namespace NullTrace {

using PacketCallback = std::function<void(PacketPtr)>;

struct CaptureStats {
    u64 packets_captured;
    u64 packets_dropped;
    u64 packets_filtered;
    u64 bytes_captured;
    u64 start_time;

    CaptureStats() : packets_captured(0), packets_dropped(0),
                     packets_filtered(0), bytes_captured(0),
                     start_time(0) {}
};

struct CaptureConfig {
    std::string interface;
    std::string filter;
    int         snaplen;
    int         timeout_ms;
    bool        promiscuous;
    bool        immediate;

    CaptureConfig() : snaplen(65535), timeout_ms(1000),
                      promiscuous(true), immediate(true) {}
};

class CaptureEngine {
public:
    explicit CaptureEngine(const CaptureConfig &config);
    ~CaptureEngine();

    bool start();
    void stop();
    bool is_running() const;

    void set_packet_callback(PacketCallback cb);
    void set_filter(const std::string &filter);

    CaptureStats get_stats() const;

    static std::vector<std::string> list_interfaces();
    static std::string              get_default_interface();

private:
    CaptureConfig           config_;
    pcap_t                 *handle_;
    std::thread             capture_thread_;
    std::atomic<bool>       running_;
    PacketCallback          callback_;
    CaptureStats            stats_;
    mutable std::mutex      stats_mutex_;
    u64                     packet_counter_;

    void capture_loop();

    static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);
};

} // namespace NullTrace
