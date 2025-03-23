/* <PCAP Programming>
 • C, C++ 기반 PCAP API를 활용하여 PACKET의 정보를 출력하는 프로그램 작성
 • Ethernet Header: src mac / dst mac
  • IP Header: src ip / dst ip
  • TCP Header: src port / dst port
  • Message도 출력하면 좋음. (적당한 길이로)
  • TCP protocol 만을 대상으로 진행 (UDP는 무시), sniff_improved.c, myheader.h코드 참고
 • *IP header, tcp header 에 있는 길이 정보를 잘 사용할 것. (ip_header_len) */

 #include <stdlib.h>
 #include <stdio.h>
 #include <pcap.h>
 #include <arpa/inet.h>
 #include <netinet/ether.h>
 #include <string.h>

// 1. Ethernet, IP, TCP의 헤더를 정의 한다. 

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    // destination host address
    u_char  ether_shost[6];    // source host address
    u_short ether_type;        // IP? ARP? RARP? etc
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, 	//IP header length
                     iph_ver:4;		//IP version
  unsigned char      iph_tos;		//Type of service
  unsigned short int iph_len;		//IP Packet length (data + header)
  unsigned short int iph_ident;		//Identification
  unsigned short int iph_flag:3,	//Fragmentation flags
                     iph_offset:13;	//Flags offset
  unsigned char      iph_ttl;		//Time to Live
  unsigned char      iph_protocol;	//Protocol type
  unsigned short int iph_chksum;	//IP datagram checksum
  struct  in_addr    iph_sourceip;	//Source IP address
  struct  in_addr    iph_destip;	//Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               // source port
    u_short tcp_dport;               // destination port
    u_int   tcp_seq;                 // sequence number
    u_int   tcp_ack;                 // acknowledgement number
    u_char  tcp_offx2;               // data offset, rsvd
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 // window
    u_short tcp_sum;                 // checksum
    u_short tcp_urp;                 // urgent pointer
};



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    // 1. IP인지 확인
    if (ntohs(eth->ether_type) != 0x0800) return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    // 2. TCP인지 확인
    if (ip->iph_protocol != IPPROTO_TCP) return;

    int ip_header_len = ip->iph_ihl * 4;
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

    // 3. 패킷 정보 출력
    printf("\n====== TCP PACKET ======\n");
    printf("Source MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Destination MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));
    printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
    printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));

    // 4. HTTP 메시지에서 Host만 출력
    int tcp_header_len = ((tcp->tcp_offx2 & 0xF0) >> 4) * 4;
    const char *payload = (const char *)(packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len);
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;

    // HTTP는 주로 포트 80이므로, 80번 통신인 경우만 시도
    if (ntohs(tcp->tcp_dport) == 80 || ntohs(tcp->tcp_sport) == 80) {
        if (payload_len > 0) {
            const char *host_ptr = strstr(payload, "Host:");
            if (host_ptr != NULL) {
                printf("Host: ");
                for (int i = 0; i < payload_len; i++) {
                    if (host_ptr[i] == '\r' || host_ptr[i] == '\n') {
                        printf("\n");
                        break;
                    }
                    printf("%c", host_ptr[i]);
                }
            }
        }
    }
}

int main(){

    //TCP only
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;


    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
          pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
     }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   //Close the handle
    return 0;
}