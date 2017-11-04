// http://docs.huihoo.com/doxygen/openssl/1.0.1c/include_2openssl_2aes_8h.html

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>

#define BUFFER_SIZE 1024

struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

struct args {
    int sock;
    char *key; // Make constant
};

typedef struct args args;

// https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl
void init_ctr(struct ctr_state *state, const unsigned char iv[]) {
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

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

void send_data(int sock_fd, AES_KEY aes_key, char buffer[], int size) {
    struct ctr_state state;
    unsigned char iv[8];

    if(!RAND_bytes(iv, 8)) {
        fprintf(stderr, "Error generating random bytes for IV\n");
        exit(EXIT_FAILURE);
    }

    char encrypted_data[size + 8];
    memcpy(encrypted_data, iv, 8);

    unsigned char encryption[size];
    init_ctr(&state, iv);
    AES_ctr128_encrypt(buffer, encryption, size, &aes_key, state.ivec, state.ecount, &state.num);
    memcpy(encrypted_data + 8, encryption, size);

    write(sock_fd, encrypted_data, size + 8);
}

void receive_data(int sock_fd, AES_KEY aes_key, char buffer[], int size) {
    struct ctr_state state;
    unsigned char iv[8];

    memcpy(iv, buffer, 8);
    init_ctr(&state, iv);

    unsigned char decrypted_data[size - 8];

    AES_ctr128_encrypt(buffer + 8, decrypted_data, size - 8, &aes_key, state.ivec, state.ecount, &state.num);

    write(STDOUT_FILENO, decrypted_data, size - 8);
}

void client_side_proxy(struct hostent *destination_host, int destination_port, char *key) {
    int sock_fd, n;
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

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    fcntl(sock_fd, F_SETFL, O_NONBLOCK);

    char buffer[BUFFER_SIZE];
    AES_KEY aes_key;

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Error in setting encryption key");
        exit(EXIT_FAILURE);
    }

    while (1) {
        while ((n = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
            send_data(sock_fd, aes_key, buffer, BUFFER_SIZE);
        }

        while ((n = read(sock_fd, buffer, BUFFER_SIZE)) > 0) {
            receive_data(sock_fd, aes_key, buffer, BUFFER_SIZE);
        }
    }
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
        client_side_proxy(destination_host, destination_port, keybuffer);
    }

    return 0;
}
