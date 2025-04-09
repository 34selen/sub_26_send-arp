
#include "send-arp.h"


int get_my_info(const char *iface, uint8_t my_mac[6], uint8_t my_ip[4]) {
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return -1;

    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) return -1;
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) return -1;
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(my_ip, &ipaddr->sin_addr, 4);

    close(fd);
    return 0;
}   


int get_others_mac(const char *iface, const char *target_ip_str, unsigned char mac_out[6]) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = iface;
    uint8_t my_mac[6], my_ip[4];
    uint8_t target_ip[4];

    if (inet_pton(AF_INET, target_ip_str, target_ip) != 1) {
        fprintf(stderr, "Invalid IP address format: %s\n", target_ip_str);
        return 1;
    }

    // 내 MAC/IP 주소 가져오기
    if (get_my_info(device, my_mac, my_ip) != 0) {
        fprintf(stderr, "인터페이스 정보를 가져올 수 없습니다: %s\n", device);
        return 1;
    }

    // pcap 핸들 열기
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        return 1;
    }

    // ARP 패킷 생성
    uint8_t packet[42];  // Ethernet(14) + ARP(28)
    struct ether_header *eth = (struct ether_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + ETHER_HDR_LEN);

    // Ethernet 헤더
    memset(eth->ether_dhost, 0xFF, 6);             // Broadcast
    memcpy(eth->ether_shost, my_mac, 6);           // 내 MAC 주소
    eth->ether_type = htons(ETHERTYPE_ARP);

    // ARP 헤더
    arp->htype = htons(1);                         // Ethernet
    arp->ptype = htons(ETHERTYPE_IP);              // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(1);                          // 요청(1)
    memcpy(arp->sha, my_mac, 6);
    memcpy(arp->spa, my_ip, 4);
    memset(arp->tha, 0x00, 6);
    memcpy(arp->tpa, target_ip, 4);

    // 패킷 전송
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "패킷 전송 실패: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // 응답 대기 및 파싱
    struct pcap_pkthdr *header;
    const u_char *recv_packet;
    int res;
    time_t start = time(NULL);

    while ((res = pcap_next_ex(handle, &header, &recv_packet)) >= 0) {
        if (res == 0) {
            if (time(NULL) - start > 3) break; // 3초 타임아웃
            continue;
        }

        struct ether_header *eth_hdr = (struct ether_header *)recv_packet;

        // ARP 패킷인지 확인
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            struct arp_header *recv_arp = (struct arp_header *)(recv_packet + ETHER_HDR_LEN);

            // 응답이면서 우리가 요청한 대상 IP에 대한 응답인지 확인
            if (ntohs(recv_arp->oper) == 2 && memcmp(recv_arp->spa, target_ip, 4) == 0) {
                memcpy(mac_out, recv_arp->sha, 6);
                pcap_close(handle);
                return 0;  // 성공
            }
        }

        if (time(NULL) - start > 3) break;  // 타임아웃
    }

    pcap_close(handle);
    fprintf(stderr, "ARP 응답을 받지 못했습니다\n");
    return 1;
}

int send_arp(const char *iface, const char *sender_ip, const char *target_ip_str, struct ether_addr *sender_mac) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *device = iface;
    uint8_t my_mac[6], my_ip[4];
    uint8_t target_ip[4];

    if (inet_pton(AF_INET, target_ip_str, target_ip) != 1) {
        fprintf(stderr, "Invalid IP address format: %s\n", target_ip_str);
        return 1;
    }

    // 내 MAC/IP 주소 가져오기
    if (get_my_info(device, my_mac, my_ip) != 0) {
        fprintf(stderr, "인터페이스 정보를 가져올 수 없습니다: %s\n", device);
        return 1;
    }

    // pcap 핸들 열기
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        return 1;
    }

    // ARP 패킷 생성
    uint8_t packet[42];  // Ethernet(14) + ARP(28)
    struct ether_header *eth = (struct ether_header *)packet;
    struct arp_header *arp = (struct arp_header *)(packet + ETHER_HDR_LEN);

    // Ethernet 헤더
    memcpy(eth->ether_dhost, sender_mac, 6);             // Broadcast
    memcpy(eth->ether_shost, my_mac, 6);           // 내 MAC 주소
    eth->ether_type = htons(ETHERTYPE_ARP);

    // ARP 헤더
    arp->htype = htons(1);                         // Ethernet
    arp->ptype = htons(ETHERTYPE_IP);              // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(2);                          // arp reply(1)
    memcpy(arp->sha, my_mac, 6);
    memcpy(arp->spa, target_ip, 4);
    memcpy(arp->tha, sender_mac, 6);
    memcpy(arp->tpa, sender_ip, 4);

    // 패킷 전송
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "패킷 전송 실패: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    printf("successfully send arp packet");
    return 0;
}