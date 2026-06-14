#include "../../include/capture/capture.hpp"
#include "../../include/capture/parser.hpp"
#include <iostream>
#include <cstring>
#include <ifaddrs.h>

namespace NullTrace {

CaptureEngine::CaptureEngine(const CaptureConfig &config)
    : config_(config), handle_(nullptr), running_(false), packet_counter_(0) {}

CaptureEngine::~CaptureEngine() {
    stop();
}

bool CaptureEngine::start() {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle_ = pcap_open_live(
        config_.interface.c_str(),
        config_.snaplen,
        config_.promiscuous ? 1 : 0,
        config_.timeout_ms,
        errbuf
    );

    if (!handle_) {
        std::cerr << "[ERR] pcap_open_live failed: " << errbuf << "\n";
        return false;
    }

    if (!config_.filter.empty()) {
        struct bpf_program fp;
        bpf_u_int32 net = 0, mask = 0;
        pcap_lookupnet(config_.interface.c_str(), &net, &mask, errbuf);

        if (pcap_compile(handle_, &fp, config_.filter.c_str(), 1, mask) == -1) {
            std::cerr << "[ERR] Filter compile failed: " << pcap_geterr(handle_) << "\n";
            return false;
        }

        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "[ERR] Filter apply failed: " << pcap_geterr(handle_) << "\n";
            pcap_freecode(&fp);
            return false;
        }
        pcap_freecode(&fp);
    }

    running_ = true;
    stats_.start_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    capture_thread_ = std::thread(&CaptureEngine::capture_loop, this);
    return true;
}

void CaptureEngine::stop() {
    running_ = false;
    if (handle_) {
        pcap_breakloop(handle_);
    }
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool CaptureEngine::is_running() const {
    return running_;
}

void CaptureEngine::set_packet_callback(PacketCallback cb) {
    callback_ = cb;
}

void CaptureEngine::set_filter(const std::string &filter) {
    config_.filter = filter;
}

CaptureStats CaptureEngine::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void CaptureEngine::capture_loop() {
    pcap_loop(handle_, -1, pcap_callback, reinterpret_cast<u_char*>(this));
}

void CaptureEngine::pcap_callback(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
    auto *engine = reinterpret_cast<CaptureEngine*>(user);
    if (!engine->running_) return;

    auto ts  = std::chrono::system_clock::now();
    auto pkt = PacketParser::parse(data, hdr->len, hdr->caplen, ts, ++engine->packet_counter_);

    {
        std::lock_guard<std::mutex> lock(engine->stats_mutex_);
        engine->stats_.packets_captured++;
        engine->stats_.bytes_captured += hdr->len;
    }

    if (engine->callback_) {
        engine->callback_(pkt);
    }
}

std::vector<std::string> CaptureEngine::list_interfaces() {
    std::vector<std::string> ifaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[ERR] Cannot find interfaces: " << errbuf << "\n";
        return ifaces;
    }

    for (pcap_if_t *dev = alldevs; dev; dev = dev->next) {
        ifaces.push_back(std::string(dev->name));
    }

    pcap_freealldevs(alldevs);
    return ifaces;
}

std::string CaptureEngine::get_default_interface() {
    char errbuf[PCAP_ERRBUF_SIZE];
    auto ifaces = list_interfaces();
    return ifaces.empty() ? "eth0" : ifaces[0];
}

} // namespace NullTrace
