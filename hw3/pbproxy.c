#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

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

int main(int argc, char *argv[]) {
    int option, server = 0;
    char *keyfile = NULL, *listen_port = NULL, *destination = NULL, *port = NULL;
    char *keybuffer;

    while ((option = getopt(argc, argv, "l:k:")) != -1) {
        switch (option) {
            case 'l':
                server = 1;
                listen_port = optarg;
                break;
            case 'k':
                keyfile = optarg;
                break;
            default:
                return -1;
        }
    }

    if (optind == argc - 2) {
        destination = argv[optind];
        port = argv[optind + 1];
    } else {
        fprintf(stderr, "%s: Invalid destination and port", argv[0]);
        return -1;
    }

    if (keyfile == NULL) {
        fprintf(stderr, "%s: Please specify keyfile", argv[0]);
        return -1;
    }

    keybuffer = read_keyfile(keyfile);
    printf("%s", keybuffer);

    return 0;
}
