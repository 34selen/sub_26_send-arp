#include <stdint.h>       // uint8_t, uint16_t, uint32_t
#include <netinet/in.h>   // struct in_addr (IP 주소)
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/ether.h>

#define LIBNET_LIL_ENDIAN 1

int get_others_mac(const char *iface, const char *target_ip_str, unsigned char mac_out[6]);
int get_my_mac(const char *iface, unsigned char mac_out[6]);
int send_arp(const char *iface, const char *sender_ip, const char *target_ip_str, struct ether_addr *sender_mac);
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
 struct libnet_ipv4_hdr
 {
 #if (LIBNET_LIL_ENDIAN)
     u_int8_t ip_hl:4,      /* header length */
            ip_v:4;         /* version */
 #endif
 #if (LIBNET_BIG_ENDIAN)
     u_int8_t ip_v:4,       /* version */
            ip_hl:4;        /* header length */
 #endif
     u_int8_t ip_tos;       /* type of service */
 #ifndef IPTOS_LOWDELAY
 #define IPTOS_LOWDELAY      0x10
 #endif
 #ifndef IPTOS_THROUGHPUT
 #define IPTOS_THROUGHPUT    0x08
 #endif
 #ifndef IPTOS_RELIABILITY
 #define IPTOS_RELIABILITY   0x04
 #endif
 #ifndef IPTOS_LOWCOST
 #define IPTOS_LOWCOST       0x02
 #endif
     u_int16_t ip_len;         /* total length */
     u_int16_t ip_id;          /* identification */
     u_int16_t ip_off;
 #ifndef IP_RF
 #define IP_RF 0x8000        /* reserved fragment flag */
 #endif
 #ifndef IP_DF
 #define IP_DF 0x4000        /* dont fragment flag */
 #endif
 #ifndef IP_MF
 #define IP_MF 0x2000        /* more fragments flag */
 #endif 
 #ifndef IP_OFFMASK
 #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
 #endif
     u_int8_t ip_ttl;          /* time to live */
     u_int8_t ip_p;            /* protocol */
     u_int16_t ip_sum;         /* checksum */
     struct in_addr ip_src, ip_dst; /* source and dest address */
 };

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
 struct libnet_tcp_hdr
 {
     u_int16_t th_sport;       /* source port */
     u_int16_t th_dport;       /* destination port */
     u_int32_t th_seq;          /* sequence number */
     u_int32_t th_ack;          /* acknowledgement number */
 #if (LIBNET_LIL_ENDIAN)
     u_int8_t th_x2:4,         /* (unused) */
            th_off:4;        /* data offset */
 #endif
 #if (LIBNET_BIG_ENDIAN)
     u_int8_t th_off:4,        /* data offset */
            th_x2:4;         /* (unused) */
 #endif
     u_int8_t  th_flags;       /* control flags */
 #ifndef TH_FIN
 #define TH_FIN    0x01      /* finished send data */
 #endif
 #ifndef TH_SYN
 #define TH_SYN    0x02      /* synchronize sequence numbers */
 #endif
 #ifndef TH_RST
 #define TH_RST    0x04      /* reset the connection */
 #endif
 #ifndef TH_PUSH
 #define TH_PUSH   0x08      /* push data to the app layer */
 #endif
 #ifndef TH_ACK
 #define TH_ACK    0x10      /* acknowledge */
 #endif
 #ifndef TH_URG
 #define TH_URG    0x20      /* urgent! */
 #endif
 #ifndef TH_ECE
 #define TH_ECE    0x40
 #endif
 #ifndef TH_CWR   
 #define TH_CWR    0x80
 #endif
     u_int16_t th_win;         /* window */
     u_int16_t th_sum;         /* checksum */
     u_int16_t th_urp;         /* urgent pointer */
 };

#pragma pack(push, 1)
struct arp_header {
    uint16_t htype;      // Hardware Type
    uint16_t ptype;      // Protocol Type
    uint8_t hlen;        // Hardware Address Length
    uint8_t plen;        // Protocol Address Length
    uint16_t oper;       // Operation
    uint8_t sha[6];      // Sender hardware address (MAC)
    uint8_t spa[4];      // Sender protocol address (IP)
    uint8_t tha[6];      // Target hardware address (MAC)
    uint8_t tpa[4];      // Target protocol address (IP)
};
#pragma pack(pop)