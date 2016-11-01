#include <crypto_box.h>
#include <crypto_hash.h>
#include <randombytes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <getopt.h>

#define range(i, a, b) for (i = a; i < b; i++)

// TODO: Better version of this?
static void *(*const volatile memset_s)(void*, int, size_t) = memset;

char hex_digits[16] = "0123456789abcdef";

void to_hex(size_t len, const uint8_t src[len], char dst[2*len]) {
    int i;
    range(i, 0, len) {
        uint8_t b = src[i];
        dst[2*i+0] = hex_digits[b >> 4];
        dst[2*i+1] = hex_digits[b&0x0f];
    }
}

uint8_t from_hex_digit(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        fprintf(stderr, "Invalid hex digit: %c\n", c);
        exit(1);
    }
}

// TODO: Needs to be hardened as it runs on user input (what if a char isn't in
//       [0-9a-f]
void from_hex(size_t len, const char src[2*len], uint8_t dst[len]) {
    int i;
    range(i, 0, len) {
        dst[i] = (from_hex_digit(src[2*i+0]) << 4) | from_hex_digit(src[2*i+1]);
    }
}

void fatal(int err, const char *message) {
    if (err == -1) {
        perror(message);
        exit(1);
    }
}

void show(size_t len, uint8_t data[len]) {
    size_t i;
    range(i, 0, len) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void store_secret_key(const char *path, size_t len, const uint8_t key[len]) {
    int fd = open(path, O_WRONLY, S_IRUSR);

    fatal(fd, "open");

    static const char label[] = {'s', 'e', 'c', 'r', 'e', 't', ' '};
    char buffer[sizeof label + 2*len + 1];

    memcpy(buffer, label, sizeof label);
    to_hex(len, key, &buffer[sizeof label]);
    buffer[sizeof label + 2*len] = '\n';

    fatal(write(fd, buffer, sizeof buffer), "write");
    fatal(close(fd), "close");
}

void store_public_key(const char *path, size_t len, const uint8_t key[len]) {
    int fd = open(path, O_WRONLY, S_IRUSR|S_IRGRP|S_IROTH);

    fatal(fd, "open");

    static const char label[] = {'p', 'u', 'b', 'l', 'i', 'c', ' '};
    char buffer[sizeof label + 2*len + 1];

    memcpy(buffer, label, sizeof label);
    to_hex(len, key, &buffer[sizeof label]);
    buffer[sizeof buffer - 1] = '\n';

    fatal(write(fd, buffer, sizeof buffer), "write");
    fatal(close(fd), "close");
}

void *load_file(int fd, size_t zero_padding, size_t *size) {
    static const size_t initial_capacity = 1<<14;
    static const size_t min_read = 1<<14;

    size_t filled = zero_padding;
    size_t capacity = zero_padding + initial_capacity;
    uint8_t *buffer = malloc(capacity);
    memset(buffer, 0, zero_padding);

    for (;;) {
        if (capacity - filled < min_read) {
            buffer = realloc(buffer, 2*capacity);
        }

        ssize_t nr = read(fd, &buffer[filled], capacity - filled);

        if (nr == -1) {
            free(buffer);
            perror("read");
            exit(1);
        } else if (nr == 0) {
            break;
        } else {
            filled += nr;
        }
    }

    *size = filled;

    return buffer;
}

// TODO: what about pbkdf stuff?
// TODO: do we really want to use labels for everything?
void load_key(const char *path, const char *expected_label, size_t len, uint8_t key[len]) {
    int fd = open(path, O_RDONLY);
    fatal(fd, "open");

    size_t size;
    uint8_t *data = load_file(fd, 0, &size);

    if (memcmp(data, expected_label, strlen(expected_label)) != 0) {
        fprintf(stderr, "Expected %s to start with label %s, aborting.\n", path, expected_label);
        exit(1);
    }

    if (size < strlen(expected_label) + 2*len) {
        fprintf(stderr, "File %s has contains %zu bytes but we need %zu\n", path, size, strlen(expected_label) + 2*len);
        exit(1);
    }

    from_hex(len, (char*)&data[strlen(expected_label)], key);
}

void cmd_box_keypair(int argc, char *argv[argc]) {
    char *public_keyfile = NULL;
    char *secret_keyfile = NULL;

    int c;
    while ((c = getopt(argc, argv, "p:s:")) != -1) {
        switch (c) {
        case 'p':
            public_keyfile = optarg;
            break;
        case 's':
            secret_keyfile = optarg;
            break;
        default:
            abort();
        }
    }

    if (!public_keyfile) {
        fprintf(stderr, "Public keyfile must be specified with -p.\n");
        exit(1);
    }

    if (!secret_keyfile) {
        fprintf(stderr, "Secret keyfile must be specified with -s.\n");
        exit(1);
    }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk, sk);

    store_public_key(public_keyfile, sizeof pk, pk);
    store_secret_key(secret_keyfile, sizeof sk, sk);

    memset_s(sk, 0, sizeof sk);
}

void cmd_box_make(int argc, char *argv[argc]) {
    const char *public_keyfile = NULL;
    const char *secret_keyfile = NULL;
    const char *message_file = NULL;
    const char *ciphertext_file = NULL;

    {
    char c;
    while ((c = getopt(argc, argv, "m:c:p:s:")) != -1) {
        switch (c) {
        case 'p':
            public_keyfile = optarg;
            break;
        case 's':
            secret_keyfile = optarg;
            break;
        case 'm':
            message_file = optarg;
            break;
        case 'c':
            ciphertext_file = optarg;
            break;
        case '?':
            abort();
        }
    }
    }

    if (!public_keyfile) {
        fprintf(stderr, "Public keyfile must be specified with -p.\n");
        exit(1);
    }

    if (!secret_keyfile) {
        fprintf(stderr, "Secret keyfile must be specified with -s.\n");
        exit(1);
    }

    if (!message_file) {
        fprintf(stderr, "Message file must be specified with -m.\n");
        exit(1);
    }

    if (!ciphertext_file) {
        fprintf(stderr, "Ciphertext file must be specified with -c.\n");
        exit(1);
    }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(public_keyfile, "public ", sizeof pk, pk);
    load_key(secret_keyfile, "secret ", sizeof sk, sk);

    int message_fd = open(message_file, O_RDONLY);
    fatal(message_fd, "open");

    size_t mlen;
    void *m = load_file(message_fd, crypto_box_ZEROBYTES, &mlen);
    fatal(close(message_fd), "close");

    uint8_t c[crypto_box_NONCEBYTES + mlen];

    randombytes(c, crypto_box_NONCEBYTES);

    crypto_box(&c[crypto_box_NONCEBYTES], m, mlen, c, pk, sk);

    int ciphertext_fd = open(ciphertext_file, O_WRONLY, S_IRUSR|S_IRGRP|S_IROTH);
    fatal(ciphertext_fd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(ciphertext_fd, c, sizeof c), "write");
    fatal(close(ciphertext_fd), "close");

    free(m);
}

void cmd_box_open(int argc, char *argv[argc]) {
    const char *public_keyfile = NULL;
    const char *secret_keyfile = NULL;
    const char *message_file = NULL;
    const char *ciphertext_file = NULL;

    {
    char c;
    while ((c = getopt(argc, argv, "m:c:p:s:")) != -1) {
        switch (c) {
        case 'p':
            public_keyfile = optarg;
            break;
        case 's':
            secret_keyfile = optarg;
            break;
        case 'm':
            message_file = optarg;
            break;
        case 'c':
            ciphertext_file = optarg;
            break;
        case '?':
            abort();
        }
    }
    }

    if (!public_keyfile) {
        fprintf(stderr, "Public keyfile must be specified with -p.\n");
        exit(1);
    }

    if (!secret_keyfile) {
        fprintf(stderr, "Secret keyfile must be specified with -s.\n");
        exit(1);
    }

    if (!message_file) {
        fprintf(stderr, "Message file must be specified with -m.\n");
        exit(1);
    }

    if (!ciphertext_file) {
        fprintf(stderr, "Ciphertext file must be specified with -c.\n");
        exit(1);
    }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(public_keyfile, "public ", sizeof pk, pk);
    load_key(secret_keyfile, "secret ", sizeof sk, sk);

    int ciphertext_fd = open(ciphertext_file, O_RDONLY);
    fatal(ciphertext_fd, "open");

    size_t full_clen;
    uint8_t *c = load_file(ciphertext_fd, 0, &full_clen);
    fatal(close(ciphertext_fd), "close");

    // TODO: check this doesn't underflow
    size_t clen = full_clen - crypto_box_NONCEBYTES;

    uint8_t m[clen];

    // TODO: Ideally change this so it doesn't include the unnecessary zeroes
    //       but until then it should at least make sure the zero bytes are
    //       cleared.
    if (crypto_box_open(m, &c[crypto_box_NONCEBYTES], clen, c, pk, sk) == -1) {
        fprintf(stderr, "open failed!\n");
        exit(1);
    }

    int message_fd = open(message_file, O_WRONLY, S_IRUSR);
    fatal(message_fd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(message_fd, &m[crypto_box_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
    fatal(close(message_fd), "close");
}

void cmd_help(int argc, char *argv[argc]) {
    fprintf(stderr, "nacl box keypair\n");
    exit(1);
}

int main(int argc, char *argv[argc]) {
    if (argc >= 3 && strcmp(argv[1], "box") == 0 && strcmp(argv[2], "keypair") == 0) {
        cmd_box_keypair(argc - 2, &argv[2]);
    } else if (argc >= 3 && strcmp(argv[1], "box") == 0 && strcmp(argv[2], "make") == 0) {
        cmd_box_make(argc - 2, &argv[2]);
    } else if (argc >= 3 && strcmp(argv[1], "box") == 0 && strcmp(argv[2], "open") == 0) {
        cmd_box_open(argc - 2, &argv[2]);
    } else {
        cmd_help(argc, argv);
    }

    return 0;
}

