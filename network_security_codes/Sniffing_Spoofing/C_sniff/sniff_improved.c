#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>  //  u_char, u_short, u_int 정의용
#include <net/ethernet.h>  // ETHERTYPE_IP, ETHERTYPE_ARP 등 정의됨

/* Ethernet header */
struct ethheader {
  uint8_t  ether_dhost[6]; /* destination host address */
  uint8_t  ether_shost[6];
  uint16_t ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, // IP header length
                     iph_ver:4; // IP version
  unsigned char      iph_tos;        // Type of service
  unsigned short int iph_len;        // IP Packet length (data + header)
  unsigned short int iph_ident;      // Identification
  unsigned short int iph_flag:3,     // Fragmentation flags
                     iph_offset:13;  // Flags offset
  unsigned char      iph_ttl;        // Time to Live
  unsigned char      iph_protocol;   // Protocol type
  unsigned short int iph_chksum;     // IP datagram checksum
  struct  in_addr    iph_sourceip;   // Source IP address
  struct  in_addr    iph_destip;     // Destination IP address
};

/* TCP Header */
struct tcpheader {
  uint16_t tcp_sport;   // (1) 출발지 포트 번호 (16비트)
  uint16_t tcp_dport;   // (2) 목적지 포트 번호 (16비트)
  uint32_t tcp_seq;     // (3) 시퀀스 번호 (32비트)
  uint32_t tcp_ack;     // (4) ACK 번호 (32비트)
  uint8_t  reserved:4;  // (5) 예약 필드 (4비트, 일반적으로 0)
  uint8_t  tcp_off:4;   // (6) 데이터 오프셋 (4비트, 헤더 길이/4)
  uint8_t  tcp_flags;   // (7) 플래그 비트들 (SYN, ACK, FIN 등)
  uint16_t tcp_win;     // (8) 윈도우 크기 (16비트, 수신 버퍼 용량)
  uint16_t tcp_sum;     // (9) 체크섬 (16비트, 오류 검출용)
  uint16_t tcp_urp;     // (10) 긴급 포인터 (16비트)
};

void show_info(const uint8_t *user, const struct pcap_pkthdr *phthdr, const uint8_t *pkt)
 {
  struct ethheader *eth = (struct ethheader *)pkt;

  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    struct ipheader *ip = (struct ipheader *)(pkt + 14);
    if (ip->iph_protocol == IPPROTO_TCP) {
      struct tcpheader *tcp = (struct tcpheader *)(pkt + 14 + (ip->iph_ihl << 2));
      int tcp_length = tcp->tcp_off << 2;
      int pl_length = ntohs(ip->iph_len) - (ip->iph_ihl << 2) - tcp_length;
      const uint8_t *payload = pkt + 14 + (ip->iph_ihl << 2) + tcp_length;

      printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
             eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

      printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
             eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

      printf("src IP: %s\n", inet_ntoa(ip->iph_sourceip));
      printf("dst IP: %s\n", inet_ntoa(ip->iph_destip));
      printf("src Port: %d\n", ntohs(tcp->tcp_sport));
      printf("dst Port: %d\n\n", ntohs(tcp->tcp_dport));

      // 128byte Message Print
      int max_length = 128;
      if (pl_length > 0) {
        printf("Message: ");
        for (int i = 0; i < pl_length && i < max_length; i++) {
          printf("%c", isprint(payload[i]) ? payload[i] : '.');
        }
        printf("\n\n\n");
      }
    }
  }
}

int main() {
  pcap_t *pkt_capture;
  char errbuf[PCAP_ERRBUF_SIZE];
  char interface[100];

  printf("Enter Interface: ");
  fgets(interface, sizeof(interface), stdin);
  interface[strlen(interface) - 1] = '\0'; // 개행 문자 제거

  pkt_capture = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (pkt_capture == NULL) {
    fprintf(stderr, "Fail: %s\n", errbuf);
    return 1;
  }

  pcap_loop(pkt_capture, 0, (pcap_handler)show_info, NULL);

  pcap_close(pkt_capture);

  return 0;
}
