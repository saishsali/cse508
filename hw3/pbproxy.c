#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

struct args {
    int sock;
    char *key; // Make constant
};

typedef struct args args;

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

void server_thread(void *args) {

}

void server_side_proxy(int listen_port, struct hostent *destination_host, int destination_port, char *key) {
    int sock_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[1024] = {0};

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = listen_port;

    if (bind(sock_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Binding failed");
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 3) < 0) {
        fprintf(stderr, "Listen failed");
        exit(EXIT_FAILURE);
    }

    pthread_t tid;
    while (1) {
        // args *arg = (args *)malloc(sizeof(args));
        // if ((arg->sock = accept(sock_fd, (struct sockaddr *)&address, sizeof(address))) < 0) {
        //     fprintf(stderr, "Accept failed");
        //     free(arg);
        //     exit(EXIT_FAILURE);
        // }
        // arg->key = key;
        // pthread_create(&tid, 0, server_thread, (void*)arg);


        if ((new_socket = accept(sock_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            fprintf(stderr, "Accept failed");
            // free(arg);
            exit(EXIT_FAILURE);
        }
        read(new_socket , buffer, 1024);
        printf("%s\n", buffer);
    }
}

void client_side_proxy(struct hostent *destination_host, int destination_port) {
    int sock_fd;
    struct sockaddr_in address;
    char *hello = "Hello from client";

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ((struct in_addr *)(destination_host->h_addr))->s_addr;
    address.sin_port = destination_port;

    if (connect(sock_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Connection failed");
        exit(EXIT_FAILURE);
    }

    send(sock_fd, hello, strlen(hello), 0);
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
        server_side_proxy(listen_port, destination_host, destination_port, keybuffer);
    } else {
        client_side_proxy(destination_host, destination_port);
    }

    return 0;
}
