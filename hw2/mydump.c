#include <stdio.h>
#include <pcap.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int option;
    char *device, error_buffer[PCAP_ERRBUF_SIZE], *interface = NULL, *file = NULL, *string = NULL, *expression = NULL;
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
                string = optarg;
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

    return 0;
}
