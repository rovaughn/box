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

const mode_t public_mode = S_IRUSR|S_IRGRP|S_IROTH;
const mode_t secret_mode = S_IRUSR;

void store_key(const char *path, mode_t mode, const char *label, size_t len, const uint8_t key[len]) {
    int fd = open(path, O_WRONLY|O_CREAT, mode);
    fatal(fd, "open");

    char buffer[strlen(label) + 2*len + 1];

    memcpy(buffer, label, strlen(label));
    to_hex(len, key, &buffer[strlen(label)]);
    buffer[strlen(label) + 2*len] = '\n';

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

typedef enum {
    cmd_success,
    cmd_usage_err,
    cmd_err,
} cmd_value;

cmd_value cmd_box_keypair(int argc, char *argv[argc]) {
    char *pkfile = NULL;
    char *skfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "p:s:")) != -1) {
            switch (c) {
            case 'p': pkfile = optarg; break;
            case 's': skfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!pkfile || !skfile) { return cmd_usage_err; }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk, sk);

    store_key(pkfile, public_mode, "public ", sizeof pk, pk);
    store_key(skfile, secret_mode, "secret ", sizeof sk, sk);

    memset_s(sk, 0, sizeof sk);

    return cmd_success;
}

cmd_value cmd_box(int argc, char *argv[argc]) {
    const char *pkfile = NULL;
    const char *skfile = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "p:s:i:o:")) != -1) {
            switch (c) {
            case 'p': pkfile = optarg; break;
            case 's': skfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!pkfile || !skfile || !infile || !outfile) { return cmd_usage_err; }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(pkfile, "public ", sizeof pk, pk);
    load_key(skfile, "secret ", sizeof sk, sk);

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t mlen;
    void *m = load_file(infd, crypto_box_ZEROBYTES, &mlen);
    fatal(close(infd), "close");

    // c[0..crypto_box_NONCEBYTES] is the nonce, c[crypto_box_NONCEBYTES..] is
    // the message
    uint8_t c[crypto_box_NONCEBYTES + mlen];

    randombytes(c, crypto_box_NONCEBYTES);
    crypto_box(&c[crypto_box_NONCEBYTES], m, mlen, c, pk, sk);

    int outfd = open(outfile, O_WRONLY|O_CREAT, S_IRUSR|S_IRGRP|S_IROTH);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, c, sizeof c), "write");
    fatal(close(outfd), "close");

    free(m);

    return cmd_success;
}

cmd_value cmd_box_open(int argc, char *argv[argc]) {
    const char *pkfile = NULL;
    const char *skfile = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "p:s:i:o:")) != -1) {
            switch (c) {
            case 'p': pkfile = optarg; break;
            case 's': skfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!pkfile || !skfile || !infile || !outfile) { return cmd_usage_err; }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(pkfile, "public ", sizeof pk, pk);
    load_key(skfile, "secret ", sizeof sk, sk);

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t full_clen;
    uint8_t *c = load_file(infd, 0, &full_clen);
    fatal(close(infd), "close");

    if (full_clen < crypto_box_NONCEBYTES) {
        fprintf(stderr, "Ciphertext is lacking a nonce.\n");
        exit(1);
    }

    size_t clen = full_clen - crypto_box_NONCEBYTES;
    uint8_t m[clen];

    // TODO: Ideally change this so it doesn't include the unnecessary zeroes
    //       but until then it should at least make sure the zero bytes are
    //       cleared.
    if (crypto_box_open(m, &c[crypto_box_NONCEBYTES], clen, c, pk, sk) == -1) {
        fprintf(stderr, "open failed!\n");
        exit(1);
    }

    int outfd = open(outfile, O_WRONLY|O_CREAT, S_IRUSR);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, &m[crypto_box_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

cmd_value cmd_box_beforenm(int argc, char *argv[argc]) {
    const char *pkfile = NULL;
    const char *skfile = NULL;
    const char *kfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "p:s:k:")) != -1) {
            switch (c) {
            case 'p': pkfile = optarg; break;
            case 's': skfile = optarg; break;
            case 'k': kfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!pkfile || !skfile || !kfile) { return cmd_usage_err; }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(pkfile, "public ", sizeof pk, pk);
    load_key(skfile, "secret ", sizeof sk, sk);

    uint8_t k[crypto_box_BEFORENMBYTES];

    crypto_box_beforenm(k, pk, sk);

    store_key(kfile, secret_mode, "beforenm ", sizeof k, k);

    return cmd_success;
}

cmd_value cmd_box_afternm(int argc, char *argv[argc]) {
    const char *kfile = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "k:i:o:")) != -1) {
            switch (c) {
            case 'k': kfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!kfile || !infile || !outfile) { return cmd_usage_err; }

    uint8_t k[crypto_box_BEFORENMBYTES];

    load_key(kfile, "beforenm ", sizeof k, k);

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t mlen;
    void *m = load_file(infd, crypto_box_ZEROBYTES, &mlen);
    fatal(close(infd), "close");

    uint8_t c[crypto_box_NONCEBYTES + mlen];

    randombytes(c, crypto_box_NONCEBYTES);

    crypto_box_afternm(&c[crypto_box_NONCEBYTES], m, mlen, c, k);

    int outfd = open(outfile, O_WRONLY|O_CREAT, public_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, c, sizeof c), "write");
    fatal(close(outfd), "close");

    free(m);

    return cmd_success;
}

cmd_value cmd_box_open_afternm(int argc, char *argv[argc]) {
    const char *kfile = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "k:i:o:")) != -1) {
            switch (c) {
            case 'k': kfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!kfile || !infile || !outfile) { return cmd_usage_err; }

    uint8_t k[crypto_box_BEFORENMBYTES];

    load_key(kfile, "beforenm ", sizeof k, k);

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t full_clen;
    uint8_t *c = load_file(infd, 0, &full_clen);
    fatal(close(infd), "close");

    // TODO: check this doesn't underflow
    size_t clen = full_clen - crypto_box_NONCEBYTES;

    uint8_t m[clen];

    // TODO: Ideally change this so it doesn't include the unnecessary zeroes
    //       but until then it should at least make sure the zero bytes are
    //       cleared.
    if (crypto_box_open_afternm(m, &c[crypto_box_NONCEBYTES], clen, c, k) == -1) {
        fprintf(stderr, "open failed!\n");
        exit(1);
    }

    int outfd = open(outfile, O_WRONLY|O_CREAT, secret_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, &m[crypto_box_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

cmd_value cmd_secretbox(int argc, char *argv[argc]) {
    const char *keyfile = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "k:i:o:")) != -1) {
            switch (c) {
            case 'k': keyfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!keyfile || !infile || !outfile) { return cmd_usage_err; }

    uint8_t k[crypto_box_BEFORENMBYTES];

    load_key(keyfile, "beforenm ", sizeof k, k);

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t full_clen;
    uint8_t *c = load_file(infd, 0, &full_clen);
    fatal(close(infd), "close");

    // TODO: check this doesn't underflow
    size_t clen = full_clen - crypto_box_NONCEBYTES;

    uint8_t m[clen];

    // TODO: Ideally change this so it doesn't include the unnecessary zeroes
    //       but until then it should at least make sure the zero bytes are
    //       cleared.
    if (crypto_box_open_afternm(m, &c[crypto_box_NONCEBYTES], clen, c, k) == -1) {
        fprintf(stderr, "open failed!\n");
        exit(1);
    }

    int outfd = open(outfile, O_WRONLY|O_CREAT, secret_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, &m[crypto_box_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

cmd_value cmd_hash(int argc, char *argv[argc]) {
    const char *infile = NULL;
    const char *outfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "i:o:")) != -1) {
            switch (c) {
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!infile || !outfile) { return cmd_usage_err; }

    int infd = open(infile, O_RDONLY);
    fatal(infd, "open");

    size_t mlen;
    uint8_t *m = load_file(infd, 0, &mlen);
    fatal(close(infd), "close");

    uint8_t h[crypto_hash_BYTES];

    crypto_hash(h, m, mlen);

    char hhex[2*crypto_hash_BYTES+1];

    to_hex(sizeof h, h, hhex);
    hhex[sizeof hhex - 1] = '\n';

    int outfd = open(outfile, O_WRONLY|O_CREAT, secret_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, hhex, sizeof hhex), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

typedef struct {
    const char *name;
    cmd_value (*func)(int argc, char *argv[argc]);
    const char *help_args;
} cmd_t;

cmd_t cmds[] = {
    {"box-keypair", cmd_box_keypair, "-p PUBLIC -s SECRET"},
    {"box", cmd_box, "-p PUBLIC -s SECRET -i IN -o OUT"},
    {"box-open", cmd_box_open, "-p PUBLIC -s SECRET -i IN -o OUT"},
    {"box-beforenm", cmd_box_beforenm, "-p PUBLIC -s SECRET -k KEYFILE"},
    {"box-afternm", cmd_box_afternm, "-k KEYFILE -i IN -o OUT"},
    {"box-open-afternm", cmd_box_open_afternm, "-k KEYFILE -i IN -o OUT"},
    {"hash", cmd_hash, "-i IN -o OUT"},
};

int main(int argc, char *argv[argc]) {
    size_t ncmds = sizeof cmds / sizeof cmds[0];

    if (argc >= 2) {
        int i;
        range(i, 0, ncmds) {
            if (strcmp(argv[1], cmds[i].name) == 0) {
                switch (cmds[i].func(argc - 1, &argv[1])) {
                case cmd_success:
                    return 0;
                case cmd_usage_err:
                    fprintf(stderr, "%s %s %s\n", argv[0], cmds[i].name, cmds[i].help_args);
                    return 2;
                default:
                    return 1;
                }
            }
        }
    }

    fprintf(stderr, "Invalid command.  Please choose one of the following:\n");

    int i;
    range(i, 0, ncmds) {
        fprintf(stderr, "%s %s %s\n", argv[0], cmds[i].name, cmds[i].help_args);
    }

    return 2;
}

