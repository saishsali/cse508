#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

#define SIZE_ETHERNET  14

#define IP_HL(ip)      (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)       (((ip)->ip_vhl) >> 4)

#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV4 0x0800


/* Ethernet header */
typedef struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
} sniff_ethernet;

/* IP header */
typedef struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
} sniff_ip;

/* TCP header */
typedef u_int tcp_seq;

typedef struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */
    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
} sniff_tcp;

typedef struct sniff_udp {
    u_short uh_sport; /* source port */
    u_short uh_dport; /* Destination port */
    u_short uh_len;   /* Header length */
    u_short uh_sum;   /* Checksum */
} sniff_udp;

void print_hex_ascii_line(const u_char *payload, int length, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < length; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (length < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (length < 16) {
        gap = 16 - length;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < length; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
}


void print_payload(const u_char *payload, int length) {
    int length_remaining = length;
    int line_width = 16;
    int line_length;
    int offset = 0;
    const u_char *ch = payload;

    if (length <= 0)
        return;

    if (length <= line_width) {
        print_hex_ascii_line(ch, length, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_length = line_width % length_remaining;

        /* print line */
        print_hex_ascii_line(ch, line_length, offset);

        /* compute total remaining */
        length_remaining = length_remaining - line_length;

        /* shift pointer to remaining bytes to print */
        ch = ch + line_length;

        /* add offset */
        offset = offset + line_width;

        /* check if we have line width chars or less */
        if (length_remaining <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, length_remaining, offset);
            break;
        }
    }
}


void print_timestamp(const struct pcap_pkthdr *header) {
    time_t time = (time_t)(header->ts.tv_sec);
    char *timestamp = ctime(&time);
    printf("Timestamp: %s", timestamp);
}

void print_mac_address(sniff_ethernet *ethernet) {
    const u_char *ch;
    int i;

    ch = ethernet->ether_shost;
    printf("Source MAC Address: ");
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%x", *ch);
        ch++;
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }

    printf("\nDestination MAC Address: ");
    ch = ethernet->ether_dhost;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%x", *ch);
        ch++;
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }
    printf("\n");
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* declare pointers to packet headers */
    const sniff_ethernet *ethernet; /* The ethernet header */
    const sniff_ip *ip;             /* The IP header */
    const sniff_tcp *tcp;           /* The TCP header */
    const sniff_udp *udp;           /* The UDP header */
    const u_char *payload;            /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_udp;
    int size_icmp;
    int size_payload;

    print_timestamp(header);

    /* Define ethernet header */
    ethernet = (sniff_ethernet *)packet;

    print_mac_address((sniff_ethernet *)ethernet);

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
        printf("Ethertype: IPV4\n");

         /* Define IP header offset */
        ip = (sniff_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            fprintf(stderr, "Invalid IP header length %u bytes\n", size_ip);
            return;
        }

        printf("Source IP address: %s\n", inet_ntoa(ip->ip_src));
        printf("Destination IP address: %s\n", inet_ntoa(ip->ip_dst));
        printf("Packet length: %d\n", ntohs(ip->ip_len));

        switch (ip->ip_p) {
            case IPPROTO_TCP:
                printf("Protocol Type: TCP\n");
                tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp) * 4;
                if (size_tcp < 20) {
                    fprintf(stderr, "Invalid TCP header length %u bytes\n", size_tcp);
                    return;
                }

                printf("Source Port: %d\n", ntohs(tcp->th_sport));
                printf("Destination Port: %d\n", ntohs(tcp->th_dport));

                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
                size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                break;
            case IPPROTO_UDP:
                printf("Protocol Type: UDP\n");
                udp = (sniff_udp *)(packet + SIZE_ETHERNET + size_ip);
                size_udp = 8;

                printf("Source Port: %d\n", ntohs(udp->uh_sport));
                printf("Destination Port: %d\n", ntohs(udp->uh_dport));

                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
                size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
                break;
            case IPPROTO_ICMP:
                printf("Protocol Type: ICMP\n");
                size_icmp = 8;
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
                size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);
                break;
            case IPPROTO_IP:
                printf("Protocol Type: IP\n");
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
                size_payload = ntohs(ip->ip_len) - size_ip;
                break;
            default:
                printf("Protocol Type: OTHER\n");
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
                size_payload = ntohs(ip->ip_len) - size_ip;
        }

        if (size_payload > 0) {
            print_payload(payload, size_payload);
        }

    } else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        printf("Ethertype: ARP\n");
    } else {
        printf("Ethertype: Unknown\n");
    }

    printf("\n");
}


int main(int argc, char *argv[]) {
    int option;
    char error_buffer[PCAP_ERRBUF_SIZE], *interface = NULL, *file = NULL, *str = NULL, *expression = NULL;
    pcap_t *handle;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program fp;

    while ((option = getopt(argc, argv, "i:r:s:")) != -1) {
        switch (option) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                file = optarg;
                break;
            case 's':
                str = optarg;
                break;
            default:
                return -1;
        }
    }

    if (optind == argc - 1) {
        expression = argv[optind];
    } else if (optind < (argc - 1)) {
        fprintf(stderr, "%s: syntax error in filter expression: syntax error", argv[0]);
        return -1;
    }

    if (interface != NULL && file != NULL) {
        interface = NULL;
    }

    if (interface == NULL && file == NULL) {
        interface = pcap_lookupdev(error_buffer);
        if (interface == NULL) {
            fprintf(stderr, "Couldn't find default interface: %s\n", error_buffer);
            return -1;
        }
    }

    if (interface != NULL) {
        if (pcap_lookupnet(interface, &net, &mask, error_buffer) == -1) {
            fprintf(stderr, "Couldn't get netmask for interface: %s", interface);
            net = 0;
            mask = 0;
        }

        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);

        if (handle == NULL) {
            fprintf(stderr, "Couldn't open interface %s: %s\n", interface, error_buffer);
            return -1;
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Interface %s doesn't supply Ethernet headers - not supported\n", interface);
        }
    }

    if (expression != NULL) {
        if (pcap_compile(handle, &fp, expression, 0, net) == -1) {
            fprintf(stderr, "Coudn't parse filter %s: %s\n", expression, pcap_geterr(handle));
            return -1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't apply filter %s: %s\n", expression, pcap_geterr(handle));
            return -1;
        }
    }

    pcap_loop(handle, -1, process_packet, (u_char *)str);

    return 0;
}
