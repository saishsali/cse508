#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

// https://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
char *read_keyfile(char *keyfile) {
    FILE *fp = fopen(keyfile, "r");

    if (fp == NULL) {
        fprintf(stderr, "%s: Cannot open file", keyfile);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    int fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buffer = (char *)malloc(fsize + 1);
    fread(buffer, fsize, 1, fp);
    buffer[fsize] = '\0';
    fclose(fp);

    return buffer;
}

void server_side_proxy(int listen_port, struct hostent *destination_host, int destination_port) {
    int sock_fd;
    struct sockaddr_in address;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        fprintf(stderr, "Socket creation failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = listen_port;

    if (bind(sock_fd, (struct sockaddr *)&address, sizeof(address))) {
        fprintf(stderr, "Binding failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 3) < 0) {
        fprintf(stderr, "Listen failed");
        exit(EXIT_FAILURE);
    }
}

void client_side_proxy() {

}

int main(int argc, char *argv[]) {
    int option, server = 0, listen_port, destination_port;
    char *keyfile = NULL;
    char *keybuffer;
    struct hostent *destination_host;

    while ((option = getopt(argc, argv, "l:k:")) != -1) {
        switch (option) {
            case 'l':
                server = 1;
                listen_port = atoi(optarg);
                break;
            case 'k':
                keyfile = optarg;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    if (optind == argc - 2) {
        if ((destination_host = gethostbyname(argv[optind])) == 0) {
            fprintf(stderr, "%s: Invalid destination specified", argv[0]);
            exit(EXIT_FAILURE);
        }
        destination_port = atoi(argv[optind + 1]);
    } else {
        fprintf(stderr, "%s: Invalid destination and port", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (keyfile == NULL) {
        fprintf(stderr, "%s: Please specify keyfile", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((keybuffer = read_keyfile(keyfile)) == NULL) {
        fprintf(stderr, "%s: Read from key file failed", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (server == 1) {
        server_side_proxy(listen_port, destination_host, destination_port);
    } else {
        client_side_proxy();
    }

    return 0;
}
