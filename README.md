# 🕸️ NullTrace

> A high-performance network packet analyzer built from scratch in C++17.

![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## 🧠 What is NullTrace?

NullTrace is a Wireshark-inspired packet analyzer written entirely in C++17 using raw libpcap. It captures live network traffic, dissects protocols layer by layer, tracks network flows, and presents real-time statistics — all from a clean terminal interface.

No GUI bloat. No dependencies beyond libpcap. Just raw packets and clean output.

---

## 🚀 Features

### 📡 Live Packet Capture
- Captures live traffic via libpcap on any network interface
- Promiscuous mode support for full network visibility
- BPF filter support (same syntax as Wireshark/tcpdump)
- Packet count limiting with -c flag

### 🧬 Protocol Dissection
- Layer 2: Ethernet, ARP
- Layer 3: IPv4, IPv6
- Layer 4: TCP, UDP, ICMP
- Layer 7: HTTP, HTTPS, DNS, FTP, SSH, SMTP, Telnet

### 📊 Real-time Analysis
- Flow tracking with per-flow packet and byte counts
- Top talkers by packet volume
- Top destination ports
- Protocol distribution breakdown
- Total bytes and packet statistics

### 🖥️ Terminal UI
- Color-coded output per protocol
- TCP flag highlighting (SYN, ACK, FIN, RST, PSH, URG)
- Hex dump support for raw packet inspection
- Human-readable byte formatting (B/KB/MB)

---

## 📁 Project Structure

```
NullTrace/
├── include/
│   ├── types.hpp
│   ├── packet.hpp
│   ├── capture/
│   │   ├── capture.hpp
│   │   └── parser.hpp
│   ├── analysis/
│   │   └── analyzer.hpp
│   └── ui/
│       └── display.hpp
├── src/
│   ├── main.cpp
│   ├── capture/
│   │   ├── capture.cpp
│   │   └── parser.cpp
│   ├── analysis/
│   │   └── analyzer.cpp
│   └── ui/
│       └── display.cpp
└── CMakeLists.txt
```

---

## 🛠️ Build Requirements

| Tool | Purpose |
|------|---------|
| g++ / clang++ | C++17 compiler |
| cmake 3.16+ | Build system |
| libpcap | Packet capture library |

### macOS

```bash
brew install cmake libpcap
```

### Linux

```bash
sudo apt install cmake libpcap-dev
```

---

## 🔨 Building

```bash
git clone https://github.com/compiledbyutkarsh/NullTrace
cd NullTrace
mkdir build && cd build
cmake ..
make -j4
```

---

## 💻 Usage

```bash
# List available interfaces
./nulltrace -l

# Capture on interface
sudo ./nulltrace -i en0

# Capture with BPF filter
sudo ./nulltrace -i en0 -f 'tcp port 443'

# Capture 100 packets then show stats
sudo ./nulltrace -i en0 -c 100 -s

# Capture only DNS traffic
sudo ./nulltrace -i en0 -f 'udp port 53' -s
```

---

## 📌 Roadmap

- [ ] PCAP file export and replay
- [ ] DNS query/response parsing
- [ ] HTTP request/response reconstruction
- [ ] JSON output mode
- [ ] Anomaly detection (port scans, SYN floods)
- [ ] IPv6 flow tracking

---

## 📜 License

MIT License - free to use, study, and build upon.

---

<p align="center">Made with 🕸️ by <a href="https://github.com/compiledbyutkarsh">compiled by utkarsh</a></p>
