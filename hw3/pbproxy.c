// http://docs.huihoo.com/doxygen/openssl/1.0.1c/include_2openssl_2aes_8h.html

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>

#define BUFFER_SIZE 4096

struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];  /* ivec[0..7] is the IV, ivec[8..15] is the big-endian counter */
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

struct proxy_connection {
    int sock_fd;
    const char *key;
    struct sockaddr_in ssh_address;
};

/* https://stackoverflow.com/questions/3141860/aes-ctr-256-encryption-mode-of-operation-on-openssl */
void init_ctr(struct ctr_state *state, const unsigned char iv[]) {
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

/* https://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer */
char *read_keyfile(char *keyfile) {
    FILE *fp = fopen(keyfile, "r");

    if (fp == NULL) {
        fprintf(stderr, "%s: Cannot open file\n", keyfile);
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

void receive_data(int fd, AES_KEY aes_key, char buffer[], int size) {
    struct ctr_state state;
    unsigned char iv[8];

    memcpy(iv, buffer, 8);
    init_ctr(&state, iv);

    unsigned char decrypted_data[size - 8];

    AES_ctr128_encrypt(buffer + 8, decrypted_data, size - 8, &aes_key, state.ivec, state.ecount, &state.num);

    write(fd, decrypted_data, size - 8);
}

void* server_thread(void *args) {
    struct proxy_connection *connection = (struct proxy_connection *)args;
    struct sockaddr_in address;
    int ssh_sock_fd, n, ssh_conn = 0;

    printf("Server thread started\n");

    if ((ssh_sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "SSH socket creation failed\n");
        pthread_exit(0);
    }

    if (connect(ssh_sock_fd, (struct sockaddr *)&connection->ssh_address, sizeof(connection->ssh_address)) < 0) {
        fprintf(stderr, "SSH connection failed\n");
        pthread_exit(0);
    }

    int flags = fcntl(connection->sock_fd, F_GETFL, 0);
    fcntl(connection->sock_fd, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(ssh_sock_fd, F_GETFL, 0);
    fcntl(ssh_sock_fd, F_SETFL, flags | O_NONBLOCK);

    char buffer[BUFFER_SIZE];
    AES_KEY aes_key;

    if (AES_set_encrypt_key(connection->key, 128, &aes_key) < 0) {
        fprintf(stderr, "Error in setting encryption key\n");
        pthread_exit(0);
    }

    while (1) {
        while ((n = read(connection->sock_fd, buffer, BUFFER_SIZE)) > 0) {
            receive_data(ssh_sock_fd, aes_key, buffer, n);
            // write(ssh_sock_fd, buffer, n);
            if (n < BUFFER_SIZE)
                break;
        }

        while ((n = read(ssh_sock_fd, buffer, BUFFER_SIZE)) >= 0) {
            if (n > 0) {
                send_data(connection->sock_fd, aes_key, buffer, n);
                // write(connection->sock_fd, buffer, n);
            }

            if (ssh_conn == 0 && n == 0) {
                ssh_conn = 1;
            }

            if (n < BUFFER_SIZE)
                break;
        }

        if (ssh_conn == 1)
            break;
    }
    printf("Server thread Finished\n");
}

void server_side_reverse_proxy(int listen_port, struct hostent *destination_host, int destination_port, char *key) {
    int sock_fd, new_socket, n, opt = 1;
    struct sockaddr_in address, ssh_address;
    int addr_len = sizeof(address);

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation failed\n");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(listen_port);

    ssh_address.sin_family = AF_INET;
    ssh_address.sin_addr.s_addr = ((struct in_addr *)(destination_host->h_addr))->s_addr;
    ssh_address.sin_port = htons(destination_port);

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        fprintf(stderr, "Reuse of address/port failed\n");
        exit(EXIT_FAILURE);
    }

    if (bind(sock_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Binding failed\n");
        exit(EXIT_FAILURE);
    }

    if (listen(sock_fd, 10) < 0) {
        fprintf(stderr, "Listen failed\n");
        exit(EXIT_FAILURE);
    }

    struct proxy_connection *connection;
    pthread_t tid;

    while (1) {
        connection = (struct proxy_connection *)malloc(sizeof(struct proxy_connection));
        if ((connection->sock_fd = accept(sock_fd, (struct sockaddr *)&address, (socklen_t *)&addr_len)) > 0) {
            connection->ssh_address = ssh_address;
            connection->key = key;
            pthread_create(&tid, 0, server_thread, (void *)connection);
            pthread_detach(tid);
        }
        // To do: When to free connection?
    }
}

void client_side_proxy(struct hostent *destination_host, int destination_port, char *key) {
    int sock_fd, n;
    struct sockaddr_in address;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = ((struct in_addr *)(destination_host->h_addr))->s_addr;
    address.sin_port = htons(destination_port);

    if (connect(sock_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Connection failed\n");
        exit(EXIT_FAILURE);
    }

    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    flags = fcntl(sock_fd, F_GETFL, 0);
    fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    char buffer[BUFFER_SIZE];
    AES_KEY aes_key;

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Error in setting encryption key\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        while ((n = read(STDIN_FILENO, buffer, BUFFER_SIZE)) > 0) {
            send_data(sock_fd, aes_key, buffer, n);
            // write(sock_fd, buffer, n);
            if (n < BUFFER_SIZE)
                break;
        }

        while ((n = read(sock_fd, buffer, BUFFER_SIZE)) > 0) {
            receive_data(STDOUT_FILENO, aes_key, buffer, n);
            // write(STDOUT_FILENO, buffer, n);
            if (n < BUFFER_SIZE)
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    int option, server_mode = 0, listen_port, destination_port;
    char *keyfile = NULL, *keybuffer;
    struct hostent *destination_host;

    /* Get options from command line arguments */
    while ((option = getopt(argc, argv, "l:k:")) != -1) {
        switch (option) {
            case 'l':
                server_mode = 1;
                listen_port = atoi(optarg);
                break;
            case 'k':
                keyfile = optarg;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    // Get destination host and port number
    if (optind == argc - 2) {
        if ((destination_host = gethostbyname(argv[optind])) == 0) {
            fprintf(stderr, "%s: Invalid destination specified\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        destination_port = atoi(argv[optind + 1]);
    } else {
        fprintf(stderr, "%s: Invalid destination and port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (keyfile == NULL) {
        fprintf(stderr, "%s: Please specify keyfile\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((keybuffer = read_keyfile(keyfile)) == NULL) {
        fprintf(stderr, "%s: Read from key file failed\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (server_mode == 1) {
        server_side_reverse_proxy(listen_port, destination_host, destination_port, keybuffer);
    } else {
        client_side_proxy(destination_host, destination_port, keybuffer);
    }

    return 0;
}
