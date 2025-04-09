#include "send-arp.h"

int main(int argc, char *argv[]) {
    if (argc < 4 || ((argc - 2) % 2 != 0)) {
        printf("사용법: %s <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    int pair_count = (argc - 2) / 2;

    for (int i = 0; i < pair_count; ++i) {
        const char *sender_ip = argv[2 + i * 2];  
        const char *target_ip = argv[3 + i * 2];

        unsigned char mac[6];
        printf("\n[+] ARP 요청: 인터페이스 = %s, 타겟 IP = %s\n", iface, sender_ip);

        if (get_others_mac(iface, sender_ip, mac) == 0) {
            printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			char mac_str[18];
			sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			struct ether_addr *sender_mac;
			sender_mac = ether_aton(mac_str); 
			if (sender_mac == NULL) {
				printf("MAC 주소 포맷이 잘못됐습니다\n");
				continue;
			}
			printf("MAC 주소 (hex): %02X:%02X:%02X:%02X:%02X:%02X\n",
				sender_mac->ether_addr_octet[0], sender_mac->ether_addr_octet[1], sender_mac->ether_addr_octet[2],
				sender_mac->ether_addr_octet[3], sender_mac->ether_addr_octet[4], sender_mac->ether_addr_octet[5]);
            //repry packet 
            if(send_arp(iface, sender_ip,target_ip, sender_mac)==0){
                printf("send arp success");
            }
            else{
                printf("send arp fail");
            
            }
        } else {
            printf("    → MAC 주소를 가져오지 못했습니다.\n");
			
        }


    }
	

    return 0;
}
