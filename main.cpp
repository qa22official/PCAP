#include <pcap.h>

#include <clocale>
#include <winsock2.h>
#include <windows.h>

#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")

#pragma pack(push, 1)
struct EthernetHeader {
    std::array<unsigned char, 6> dst;
    std::array<unsigned char, 6> src;
    unsigned short etherType;
};

struct IPv4Header {
    unsigned char versionAndIhl;
    unsigned char tos;
    unsigned short totalLength;
    unsigned short identification;
    unsigned short flagsAndFragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int srcIp;
    unsigned int dstIp;
};
#pragma pack(pop)

struct Counters {
    unsigned long long bytes = 0;
    unsigned long long packets = 0;
};

struct StatsBucket {
    std::unordered_map<std::string, Counters> srcMac;
    std::unordered_map<std::string, Counters> srcIp;
    std::unordered_map<std::string, Counters> dstMac;
    std::unordered_map<std::string, Counters> dstIp;
};

std::string nowAsText() {
    std::time_t now = std::time(nullptr);
    std::tm localTm{};
    localtime_s(&localTm, &now);

    std::ostringstream oss;
    oss << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string macToString(const std::array<unsigned char, 6>& mac) {
    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) {
            oss << '-';
        }
        oss << std::setw(2) << static_cast<int>(mac[i]);
    }
    return oss.str();
}

std::string ipv4ToString(unsigned int ipNetworkOrder) {
    in_addr addr{};
    addr.S_un.S_addr = ipNetworkOrder;
    const char* ipText = inet_ntoa(addr);
    if (ipText == nullptr) {
        return "0.0.0.0";
    }
    return ipText;
}

void printAdapters(const pcap_if_t* adapters) {
    std::cout << "Available adapters:\n";
    int index = 0;
    for (const pcap_if_t* d = adapters; d != nullptr; d = d->next) {
        std::cout << "  [" << index << "] "
                  << (d->description ? d->description : d->name)
                  << "\n";
        ++index;
    }
}

const pcap_if_t* pickAdapter(const pcap_if_t* adapters, int adapterIndex) {
    if (adapterIndex < 0) {
        // Auto-select first non-WAN, non-loopback adapter.
        for (const pcap_if_t* d = adapters; d != nullptr; d = d->next) {
            std::string desc = d->description ? d->description : d->name;
            std::string lower = desc;
            for (char& ch : lower) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            if (lower.find("wan miniport") == std::string::npos &&
                lower.find("loopback") == std::string::npos) {
                return d;
            }
        }
    }

    int index = 0;
    const pcap_if_t* chosen = adapters;

    while (chosen != nullptr && index < adapterIndex) {
        chosen = chosen->next;
        ++index;
    }

    return chosen;
}

void appendOneLineLog(
    std::ofstream& logFile,
    const std::string& timestamp,
    const std::string& srcMac,
    const std::string& srcIp,
    const std::string& dstMac,
    const std::string& dstIp,
    unsigned int frameLength) {
    logFile << timestamp << ','
            << srcMac << ','
            << srcIp << ','
            << dstMac << ','
            << dstIp << ','
            << frameLength << '\n';
}

void addStats(StatsBucket& stats, const std::string& srcMac, const std::string& srcIp,
              const std::string& dstMac, const std::string& dstIp, unsigned int bytes) {
    auto update = [bytes](Counters& c) {
        c.bytes += bytes;
        c.packets += 1;
    };

    update(stats.srcMac[srcMac]);
    update(stats.srcIp[srcIp]);
    update(stats.dstMac[dstMac]);
    update(stats.dstIp[dstIp]);
}

void writeCounterMap(std::ofstream& statsFile,
                     const std::string& title,
                     const std::unordered_map<std::string, Counters>& data) {
    statsFile << title << '\n';
    for (const auto& kv : data) {
        statsFile << "  " << kv.first
                  << ",bytes=" << kv.second.bytes
                  << ",packets=" << kv.second.packets
                  << '\n';
    }
    if (data.empty()) {
        statsFile << "  (no data)\n";
    }
}

void flushStats(std::ofstream& statsFile, const StatsBucket& stats,
                const std::string& windowStart, const std::string& windowEnd) {
    statsFile << "==============================\n";
    statsFile << "Time window: " << windowStart << " -> " << windowEnd << '\n';

    writeCounterMap(statsFile, "Traffic by source MAC:", stats.srcMac);
    writeCounterMap(statsFile, "Traffic by source IP:", stats.srcIp);
    writeCounterMap(statsFile, "Traffic by destination MAC:", stats.dstMac);
    writeCounterMap(statsFile, "Traffic by destination IP:", stats.dstIp);
    statsFile << std::flush;
}

bool parseIpv4Packet(int linkType,
                     const pcap_pkthdr* header,
                     const unsigned char* pktData,
                     std::string& srcMac,
                     std::string& dstMac,
                     std::string& srcIp,
                     std::string& dstIp) {
    if (header == nullptr || pktData == nullptr || header->caplen == 0) {
        return false;
    }

    if (linkType == DLT_EN10MB) {
        if (header->caplen < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            return false;
        }
        const auto* eth = reinterpret_cast<const EthernetHeader*>(pktData);
        if (ntohs(eth->etherType) != 0x0800) {
            return false;
        }
        const auto* ip = reinterpret_cast<const IPv4Header*>(pktData + sizeof(EthernetHeader));
        if ((ip->versionAndIhl >> 4) != 4) {
            return false;
        }
        srcMac = macToString(eth->src);
        dstMac = macToString(eth->dst);
        srcIp = ipv4ToString(ip->srcIp);
        dstIp = ipv4ToString(ip->dstIp);
        return true;
    }

    if (linkType == DLT_RAW || linkType == DLT_NULL) {
        size_t ipOffset = 0;
        if (linkType == DLT_NULL) {
            if (header->caplen < 4 + sizeof(IPv4Header)) {
                return false;
            }
            ipOffset = 4;
        } else {
            if (header->caplen < sizeof(IPv4Header)) {
                return false;
            }
        }

        const auto* ip = reinterpret_cast<const IPv4Header*>(pktData + ipOffset);
        if ((ip->versionAndIhl >> 4) != 4) {
            return false;
        }

        srcMac = "N/A";
        dstMac = "N/A";
        srcIp = ipv4ToString(ip->srcIp);
        dstIp = ipv4ToString(ip->dstIp);
        return true;
    }

    return false;
}

int main(int argc, char* argv[]) {
    // Ensure UTF-8 text is displayed correctly in Windows terminals.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    std::setlocale(LC_ALL, ".UTF-8");

    int adapterIndex = -1;
    int intervalSeconds = 60;
    std::string logPath = "packet_log.txt";
    std::string statsPath = "packet_stats.txt";

    if (argc >= 2) {
        logPath = argv[1];
    }
    if (argc >= 3) {
        statsPath = argv[2];
    }
    if (argc >= 4) {
        intervalSeconds = std::max(1, std::atoi(argv[3]));
    }
    if (argc >= 5) {
        adapterIndex = std::max(0, std::atoi(argv[4]));
    }

    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* adapters = nullptr;
    if (pcap_findalldevs(&adapters, errbuf) == -1) {
        std::cerr << "pcap_findalldevs failed: " << errbuf << "\n";
        return 1;
    }

    if (adapters == nullptr) {
        std::cerr << "No adapter found.\n";
        return 1;
    }

    const pcap_if_t* selected = pickAdapter(adapters, adapterIndex);
    if (selected == nullptr) {
        printAdapters(adapters);
        std::cerr << "Invalid adapter index: " << adapterIndex << "\n";
        pcap_freealldevs(adapters);
        return 1;
    }

    std::cout << "Selected adapter: " << (selected->description ? selected->description : selected->name) << "\n";

    pcap_t* handle = pcap_open_live(selected->name, 65536, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        pcap_freealldevs(adapters);
        return 1;
    }

    int linkType = pcap_datalink(handle);
    std::cout << "Link type: " << linkType << "\n";

    bpf_program fp{};
    const char* filterExpr = "ip";
    if (pcap_compile(handle, &fp, filterExpr, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        if (pcap_setfilter(handle, &fp) != 0) {
            std::cerr << "Set filter failed: " << pcap_geterr(handle) << "\n";
        }
        pcap_freecode(&fp);
    } else {
        std::cerr << "Compile filter failed: " << pcap_geterr(handle) << "\n";
    }

    std::ofstream logFile(logPath, std::ios::app);
    std::ofstream statsFile(statsPath, std::ios::app);
    if (!logFile.is_open() || !statsFile.is_open()) {
        std::cerr << "Open output files failed.\n";
        pcap_close(handle);
        pcap_freealldevs(adapters);
        return 1;
    }

    bool logNeedsHeader = true;
    try {
        logNeedsHeader = (!std::filesystem::exists(logPath) || std::filesystem::file_size(logPath) == 0);
    } catch (...) {
        logNeedsHeader = true;
    }

    if (logNeedsHeader) {
        logFile << "time,src_mac,src_ip,dst_mac,dst_ip,frame_length\n";
        logFile.flush();
    }

    StatsBucket stats{};
    unsigned long long windowPackets = 0;
    auto lastFlush = std::chrono::steady_clock::now();
    std::string windowStartText = nowAsText();

    std::cout << "Capture started. Press Ctrl+C to stop.\n";
    std::cout << "Log file: " << logPath << "\n";
    std::cout << "Stats file: " << statsPath << "\n";
    std::cout << "Stats interval: " << intervalSeconds << " seconds\n";

    while (true) {
        pcap_pkthdr* header = nullptr;
        const unsigned char* pktData = nullptr;
        int rc = pcap_next_ex(handle, &header, &pktData);

        if (rc == 0) {
            // Timeout; continue polling.
        } else if (rc == 1) {
            std::string srcMac;
            std::string dstMac;
            std::string srcIp;
            std::string dstIp;
            if (!parseIpv4Packet(linkType, header, pktData, srcMac, dstMac, srcIp, dstIp)) {
                continue;
            }

            std::string ts = nowAsText();

            appendOneLineLog(logFile, ts, srcMac, srcIp, dstMac, dstIp,
                             static_cast<unsigned int>(header->len));
            addStats(stats, srcMac, srcIp, dstMac, dstIp,
                     static_cast<unsigned int>(header->len));
            windowPackets += 1;
        } else if (rc == -1) {
            std::cerr << "Capture error: " << pcap_geterr(handle) << "\n";
            break;
        } else if (rc == -2) {
            std::cout << "Capture finished.\n";
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastFlush);
        if (elapsed.count() >= intervalSeconds) {
            std::string windowEndText = nowAsText();
            flushStats(statsFile, stats, windowStartText, windowEndText);
            if (windowPackets == 0) {
                std::cerr << "No IPv4 packets parsed in this window. "
                          << "Try another adapter index (e.g. 3/6/7) and generate traffic.\n";
            }
            stats = StatsBucket{};
            windowPackets = 0;
            windowStartText = windowEndText;
            lastFlush = now;
        }
    }

    if (!stats.srcMac.empty() || !stats.srcIp.empty() || !stats.dstMac.empty() || !stats.dstIp.empty()) {
        std::string windowEndText = nowAsText();
        flushStats(statsFile, stats, windowStartText, windowEndText);
    }

    pcap_close(handle);
    pcap_freealldevs(adapters);

    return 0;
}
