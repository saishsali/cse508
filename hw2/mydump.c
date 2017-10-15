/*
    References:
    - http://www.tcpdump.org/pcap.html
    - http://www.tcpdump.org/manpages/pcap-filter.7.html
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* Buffer size */
#define SIZE 1024

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header size is 14 bytes, UDP and ICMP are 8 bytes */
#define SIZE_ETHERNET 14
#define SIZE_UDP      8
#define SIZE_ICMP     8

/* IP Header length */
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)

/* Ethertype values for different protocols */
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_IPV4 0x0800

/* ARP Request, Reply */
#define ARP_REQUEST    1
#define ARP_REPLY      2

/* ARP Header */
typedef struct sniff_arp {
    uint16_t htype;        /* Hardware Type           */
    uint16_t ptype;        /* Protocol Type           */
    u_char hlen;           /* Hardware Address Length */
    u_char plen;           /* Protocol Address Length */
    uint16_t opcode;       /* Operation Code          */
    u_char sender_mac[6];  /* Sender hardware address */
    u_char sender_ip[4];   /* Sender IP address       */
    u_char target_mac[6];  /* Target hardware address */
    u_char target_ip[4];   /* Target IP address       */
} sniff_arp;

/* Ethernet header */
typedef struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
} sniff_ethernet;

/* IP header */
typedef struct sniff_ip {
    u_char ip_vhl;                  /* version << 4 | header length >> 2 */
    u_char ip_tos;                  /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl;                  /* time to live */
    u_char ip_p;                    /* protocol */
    u_short ip_sum;                 /* checksum */
    struct in_addr ip_src,ip_dst;   /* source and dest address */
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

/*
 * Prints payload in rows of 16 bytes in hex and ascii format
 * Example: 4e 4f 54 49 46 59 20 2a 20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.
 */
void print_hex_ascii_line(const u_char *payload, int length, int offset) {
    int i;
    int gap;
    const u_char *ch;

    printf("\n");
    /* hex */
    ch = payload;
    for(i = 0; i < length; i++) {
        printf("%02x ", *ch);
        ch++;
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
}

/* Print payload */
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
    while (1) {
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

/* Check if pattern str occurs in payload */
int check_pattern(const u_char *payload, int length, u_char *str) {
    const u_char *ch = payload;
    int i;
    u_char *ascii_payload = (u_char *)malloc(sizeof(u_char) * length + 1);

    /* If pattern is empty */
    if (str == NULL) {
        free(ascii_payload);
        return 1;
    }

    /* Create ascii payload from raw payload */
    for (i = 0; i < length; i++) {
        if (isprint(*ch))
            ascii_payload[i] = *ch;
        else
            ascii_payload[i] = '.';
        ch++;
    }
    ascii_payload[i] = '\0';

    /* Check if there is a match for str in ascii payload */
    if (strcasestr((char *)ascii_payload, (char *)str) == NULL) {
        free(ascii_payload);
        return 0;
    }

    free(ascii_payload);
    return 1;
}

/*
 * Print timestamp
 * Example: 2013-01-12 18:10:37.951621
*/
void print_timestamp(const struct pcap_pkthdr *header) {
    struct tm *tm_info;
    char timestamp[20];
    time_t timer = (time_t)(header->ts.tv_sec);
    tm_info = localtime(&timer);
    strftime(timestamp, 50, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("%s.%06ld, ", timestamp, (long int)header->ts.tv_usec);
}

/*
 * Print source and destination MAC address
 * Example: c4:3d:c7:17:6f:9b -> 01:00:5e:7f:ff:fa
*/
void print_mac_address(sniff_ethernet *ethernet) {
    const u_char *ch;
    int i;

    /* Source MAC Address */
    ch = ethernet->ether_shost;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", *ch);
        ch++;
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }
    printf(" -> ");

    /* Destination MAC Address */
    ch = ethernet->ether_dhost;
    for(i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", *ch);
        ch++;
        if (i != ETHER_ADDR_LEN - 1)
            printf(":");
    }
    printf(", ");
}

/* Callback function process packet to fetch and print packet */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /* declare pointers to packet headers */
    const sniff_ethernet *ethernet; /* The ethernet header */
    const sniff_ip *ip;             /* The IP header */
    const sniff_tcp *tcp;           /* The TCP header */
    const sniff_udp *udp;           /* The UDP header */
    const sniff_arp *arp;           /* The ARP header */
    u_char *payload = NULL;         /* Packet payload */
    char buffer[SIZE];

    int size_ip, size_tcp, size_payload = 0, i;

    /* Define ethernet header */
    ethernet = (sniff_ethernet *)packet;
    sprintf(buffer, "type 0x%x, ", ntohs(ethernet->ether_type));

    if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {
        /* Define IP header offset */
        ip = (sniff_ip *)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        if (size_ip < 20) {
            fprintf(stderr, "Invalid IP header length %u bytes\n", size_ip);
            return;
        }

        /* Packet length */
        sprintf(buffer + strlen(buffer), "length %d, ", header->len);

        /* Determine protocol */
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                /* Define TCP header offset */
                tcp = (sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp) * 4;
                if (size_tcp < 20) {
                    fprintf(stderr, "Invalid TCP header length %u bytes\n", size_tcp);
                    return;
                }

                /* Source IP.Source Port -> Destination IP.Destination Port for TCP */
                sprintf(
                    buffer + strlen(buffer), "%s.%d -> %s.%d TCP",
                    inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
                    inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport)
                );

                /* Compute TCP payload offset and size*/
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
                size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
                break;

            case IPPROTO_UDP:
                /* Define UDP header offset */
                udp = (sniff_udp *)(packet + SIZE_ETHERNET + size_ip);

                /* Source IP.Source Port -> Destination IP.Destination Port for UDP */
                sprintf(
                    buffer + strlen(buffer), "%s.%d -> %s.%d UDP",
                    inet_ntoa(ip->ip_src), ntohs(udp->uh_sport),
                    inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport)
                );

                /* Compute UDP payload offset and size*/
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
                size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
                break;

            case IPPROTO_ICMP:
                /* Source IP -> Destination IP for ICMP */
                sprintf(
                    buffer + strlen(buffer), "%s -> %s ICMP",
                    inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst)
                );

                /* Compute ICMP payload offset and size*/
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_ICMP);
                size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_ICMP);
                break;

            default:
                /* Source IP -> Destination IP for OTHER */
                sprintf(buffer + strlen(buffer), "%s -> %s OTHER", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
        }

    } else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
        arp = (sniff_arp *)(packet + SIZE_ETHERNET);

        /* Packet length and ARP Request/Reply */
        sprintf(
            buffer + strlen(buffer), "length %d, ARP %s, ", header->len,
            (ntohs(arp->opcode) == ARP_REQUEST)? "Request" : "Reply"
        );

        /* Source IP address */
        for(i = 0; i < 4; i++) {
            sprintf(buffer + strlen(buffer), "%d", arp->sender_ip[i]);
            if (i != 3) {
                sprintf(buffer + strlen(buffer), ".");
            }
        }

        sprintf(buffer + strlen(buffer), " -> ");

        /* Destination IP address */
        for(i = 0; i < 4; i++) {
            sprintf(buffer + strlen(buffer), "%d", arp->target_ip[i]);
            if (i != 3) {
                sprintf(buffer + strlen(buffer), ".");
            }
        }

    } else {
        printf("Ethertype: Unknown\n\n");
        return;
    }

    if (check_pattern(payload, size_payload, args) == 1) {
        print_timestamp(header);
        print_mac_address((sniff_ethernet *)ethernet);
        printf("%s", buffer);
        if (size_payload > 0) {
            print_payload(payload, size_payload);
        }
        printf("\n\n");
    }
}

// Start execution
int main(int argc, char *argv[]) {
    int option; /* Command line option */

    /* If a pcap command fails, error_buffer has a description of the error */
    char error_buffer[PCAP_ERRBUF_SIZE];

    /* Interface, file, string to be matched and BPF filter expression */
    char *interface = NULL, *file = NULL, *str = NULL, *expression = NULL;

    pcap_t *handle;         /* Session handle */
    bpf_u_int32 net;        /* The IP of our sniffing device */
    bpf_u_int32 mask;       /* The netmask of our sniffing device */
    struct bpf_program fp;  /* The compiled filter expression */

    /* Get options from command line arguments */
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

    // Get expression
    if (optind == argc - 1) {
        expression = argv[optind];
    } else if (optind < (argc - 1)) {
        fprintf(stderr, "%s: syntax error in filter expression: syntax error", argv[0]);
        return -1;
    }

    /* Read packet from file in case both interface and filename is provided */
    if (interface != NULL && file != NULL) {
        interface = NULL;
    }

    /* If both interface and filename is NULL */
    if (interface == NULL && file == NULL) {
        /* Setting the device */
        interface = pcap_lookupdev(error_buffer);
        if (interface == NULL) {
            fprintf(stderr, "Couldn't find default interface: %s\n", error_buffer);
            return -1;
        }
    }

    /* If interface is provided */
    if (interface != NULL) {
        /* Get IPv4 network numbers and corresponding network mask of the device */
        if (pcap_lookupnet(interface, &net, &mask, error_buffer) == -1) {
            fprintf(stderr, "Couldn't get netmask for interface: %s", interface);
            net = 0;
            mask = 0;
        }

        /* Open the device for sniffing */
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, error_buffer);

        if (handle == NULL) {
            fprintf(stderr, "Couldn't open interface %s: %s\n", interface, error_buffer);
            return -1;
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Interface %s doesn't supply Ethernet headers - not supported\n", interface);
        }
    } else if (file != NULL) { /* Else if filename is provided */
        handle = pcap_open_offline(file, error_buffer);

        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file %s: %s\n", file, error_buffer);
            return -1;
        }
    }

    /* If BPF filter is present, Filter traffic */
    if (expression != NULL) {
        /* Compile filter */
        if (pcap_compile(handle, &fp, expression, 0, net) == -1) {
            fprintf(stderr, "Coudn't parse filter %s: %s\n", expression, pcap_geterr(handle));
            return -1;
        }

        /* Apply filter */
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't apply filter %s: %s\n", expression, pcap_geterr(handle));
            return -1;
        }
    }

    /* Start sniffing with process_packet as the callback function */
    pcap_loop(handle, -1, process_packet, (u_char *)str);

    /* cleanup */
    if (expression != NULL) {
        pcap_freecode(&fp);
    }
    pcap_close(handle);

    return 0;
}
