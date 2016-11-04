#include <crypto_box.h>
#include <crypto_secretbox.h>
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
#include <stdbool.h>
#include "readpass.h"
#include "crypto_scrypt.h"

#define crypto_scrypt_SALTBYTES 32

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
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, mode);
    fatal(fd, "open");

    char buffer[strlen(label) + 1 + 2*len + 1];

    memcpy(buffer, label, strlen(label));
    buffer[strlen(label)] = ' ';
    to_hex(len, key, &buffer[strlen(label) + 1]);
    buffer[strlen(label) + 1 + 2*len] = '\n';

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

    if (size < strlen(expected_label) + 1 + 2*len) {
        fprintf(stderr, "File %s has contains %zu bytes but we need %zu\n", path, size, strlen(expected_label) + 2*len);
        exit(1);
    }

    if (memcmp(data, expected_label, strlen(expected_label)) != 0) {
        fprintf(stderr, "Expected %s to start with label %s, aborting.\n", path, expected_label);
        exit(1);
    }

    if (data[strlen(expected_label)] != ' ') {
        fprintf(stderr, "%s must have space after label, aborting.\n", path);
        exit(1);
    }

    from_hex(len, (char*)&data[strlen(expected_label) + 1], key);
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

    store_key(pkfile, public_mode, "public", sizeof pk, pk);
    store_key(skfile, secret_mode, "secret", sizeof sk, sk);

    memset_s(sk, 0, sizeof sk);

    return cmd_success;
}

cmd_value cmd_box(int argc, char *argv[argc]) {
    const char *pkfile = NULL;
    const char *skfile = NULL;
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";

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

    load_key(pkfile, "public", sizeof pk, pk);
    load_key(skfile, "secret", sizeof sk, sk);

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

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
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
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";

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

    load_key(pkfile, "public", sizeof pk, pk);
    load_key(skfile, "secret", sizeof sk, sk);

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

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
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

    load_key(pkfile, "public", sizeof pk, pk);
    load_key(skfile, "secret", sizeof sk, sk);

    uint8_t k[crypto_box_BEFORENMBYTES];

    crypto_box_beforenm(k, pk, sk);

    store_key(kfile, secret_mode, "beforenm ", sizeof k, k);

    return cmd_success;
}

cmd_value cmd_box_afternm(int argc, char *argv[argc]) {
    const char *kfile = NULL;
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";

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

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, c, sizeof c), "write");
    fatal(close(outfd), "close");

    free(m);

    return cmd_success;
}

cmd_value cmd_box_open_afternm(int argc, char *argv[argc]) {
    const char *kfile = NULL;
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";

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

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, &m[crypto_box_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

cmd_value cmd_hash(int argc, char *argv[argc]) {
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";

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

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
    fatal(outfd, "open");

    // TODO: This unnecessarily includes the zero bytes.
    fatal(write(outfd, hhex, sizeof hhex), "write");
    fatal(close(outfd), "close");

    return cmd_success;
}

cmd_value cmd_secretbox_key(int argc, char *argv[argc]) {
    const char *keyfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "k:")) != -1) {
            switch (c) {
            case 'k': keyfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!keyfile) { return cmd_usage_err; }

    uint8_t k[crypto_secretbox_KEYBYTES];

    randombytes(k, sizeof k);
    store_key(keyfile, secret_mode, "secretbox", sizeof k, k);

    return cmd_success;
}

void save_uint64(uint8_t b[8], uint64_t n) {
    int i;
    range(i, 0, 8) {
        b[i] = (n>>(8*i))&0xff;
    }
}

void save_uint32(uint8_t b[4], uint64_t n) {
    int i;
    range(i, 0, 4) {
        b[i] = (n>>(8*i))&0xff;
    }
}

uint64_t read_uint64(uint8_t b[8]) {
    uint64_t n = 0;
    int i;
    range(i, 0, 8) {
        n |= b[i] << (8*i);
    }
    return n;
}

uint32_t read_uint32(uint8_t b[4]) {
    uint64_t n = 0;
    int i;
    range(i, 0, 4) {
        n |= b[i] << (8*i);
    }
    return n;
}

struct __attribute__((__packed__)) secretbox_scrypt {
    uint8_t salt[crypto_scrypt_SALTBYTES];
    uint8_t N[8];
    uint8_t r[4];
    uint8_t p[4];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t c[];
};

cmd_value cmd_secretbox(int argc, char *argv[argc]) {
    const char *keyfile = NULL;
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";
    bool use_password = false;

    {
        char c;
        while ((c = getopt(argc, argv, "pk:i:o:")) != -1) {
            switch (c) {
            case 'p': use_password = true;
            case 'k': keyfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if ((use_password && keyfile) || (!use_password && !keyfile) || !infile || !outfile) {
        return cmd_usage_err;
    }

    if (use_password) {
        char *password;
        readpass(&password, "Password", "Confirm password", 1);

        // there are better ways of deciding these, but these are what were used
        // by the scrypt utility on my laptop.
        // N must be power of 2 greater than 1
        // r * p < 2**30
        // buflen <= (2**32 - 1) * 32
        uint64_t N = 524288;
        uint32_t r = 8;
        uint32_t p = 1;

        int infd = open(infile, O_RDONLY);
        fatal(infd, "open");

        size_t mlen;
        void *m = load_file(infd, crypto_secretbox_ZEROBYTES, &mlen);
        fatal(close(infd), "close");

        size_t clen = sizeof(struct secretbox_scrypt) + mlen;
        struct secretbox_scrypt *c = malloc(clen);

        randombytes(c->salt, sizeof c->salt);
        save_uint64(c->N, N);
        save_uint32(c->r, r);
        save_uint32(c->p, p);
        randombytes(c->nonce, sizeof c->nonce);

        uint8_t k[crypto_secretbox_KEYBYTES];

        if (crypto_scrypt(
                (uint8_t*)password, strlen(password),
                c->salt, sizeof c->salt,
                N, r, p,
                k, sizeof k
           ) == -1) {
            fprintf(stderr, "scrypt failed\n");
            exit(1);
        }

        crypto_secretbox(c->c, m, mlen, c->nonce, k);

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
        fatal(outfd, "open");

        // TODO: This unnecessarily includes the zero bytes.
        fatal(write(outfd, c, clen), "write");
        fatal(close(outfd), "close");

        free(m);

        return cmd_success;
    } else {
        uint8_t k[crypto_secretbox_KEYBYTES];

        load_key(keyfile, "secretbox", sizeof k, k);

        int infd = open(infile, O_RDONLY);
        fatal(infd, "open");

        size_t mlen;
        void *m = load_file(infd, crypto_secretbox_ZEROBYTES, &mlen);
        fatal(close(infd), "close");

        // c[0..crypto_secretbox_NONCEBYTES] is the nonce,
        // c[crypto_secretbox_NONCEBYTES..] is the message
        uint8_t c[crypto_secretbox_NONCEBYTES + mlen];

        randombytes(c, crypto_secretbox_NONCEBYTES);
        crypto_secretbox(&c[crypto_secretbox_NONCEBYTES], m, mlen, c, k);

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
        fatal(outfd, "open");

        // TODO: This unnecessarily includes the zero bytes.
        fatal(write(outfd, c, sizeof c), "write");
        fatal(close(outfd), "close");

        free(m);

        return cmd_success;
    }
}

cmd_value cmd_secretbox_open(int argc, char *argv[argc]) {
    const char *keyfile = NULL;
    const char *infile = "/dev/stdin";
    const char *outfile = "/dev/stdout";
    bool use_password = false;

    {
        char c;
        while ((c = getopt(argc, argv, "pk:i:o:")) != -1) {
            switch (c) {
            case 'p': use_password = true;
            case 'k': keyfile = optarg; break;
            case 'i': infile = optarg; break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if ((use_password && keyfile) || (!use_password && !keyfile) || !infile || !outfile) {
        return cmd_usage_err;
    }

    if (use_password) {
        char *password;
        readpass(&password, "Password", "Confirm password", 1);

        int infd = open(infile, O_RDONLY);
        fatal(infd, "open");

        size_t clen;
        struct secretbox_scrypt *c = load_file(infd, 0, &clen);
        fatal(close(infd), "close");

        if (clen < sizeof(struct secretbox_scrypt)) {
            fprintf(stderr, "Too small.");
            exit(1);
        }

        size_t mlen = clen - sizeof(struct secretbox_scrypt);
        uint8_t k[crypto_secretbox_KEYBYTES];

        if (crypto_scrypt(
                (uint8_t*)password, strlen(password),
                c->salt, sizeof c->salt,
                read_uint64(c->N), read_uint32(c->r), read_uint32(c->p),
                k, sizeof k
            ) == -1) {
            fprintf(stderr, "scrypt failed\n");
            exit(1);
        }

        uint8_t *m = malloc(mlen);

        if (crypto_secretbox_open(m, c->c, mlen, c->nonce, k) == -1) {
            fprintf(stderr, "open failed!\n");
            exit(1);
        }

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
        fatal(outfd, "open");

        fatal(write(outfd, &m[crypto_secretbox_ZEROBYTES], mlen - crypto_secretbox_ZEROBYTES), "write");
        fatal(close(outfd), "close");

        return cmd_success;
    } else {
        uint8_t k[crypto_secretbox_KEYBYTES];

        load_key(keyfile, "secretbox", sizeof k, k);

        int infd = open(infile, O_RDONLY);
        fatal(infd, "open");

        size_t full_clen;
        uint8_t *c = load_file(infd, 0, &full_clen);
        fatal(close(infd), "close");

        if (full_clen < crypto_secretbox_NONCEBYTES) {
            fprintf(stderr, "Ciphertext is lacking a nonce.\n");
            exit(1);
        }

        size_t clen = full_clen - crypto_secretbox_NONCEBYTES;
        uint8_t m[clen];

        // TODO: Ideally change this so it doesn't include the unnecessary zeroes
        //       but until then it should at least make sure the zero bytes are
        //       cleared.
        if (crypto_secretbox_open(m, &c[crypto_secretbox_NONCEBYTES], clen, c, k) == -1) {
            fprintf(stderr, "open failed!\n");
            exit(1);
        }

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
        fatal(outfd, "open");

        // TODO: This unnecessarily includes the zero bytes.
        fatal(write(outfd, &m[crypto_secretbox_ZEROBYTES], sizeof m - crypto_box_ZEROBYTES), "write");
        fatal(close(outfd), "close");

        return cmd_success;
    }
}

cmd_value cmd_random(int argc, char *argv[argc]) {
    const char *outfile = "/dev/stdout";
    size_t n = 0;

    {
        char c;
        while ((c = getopt(argc, argv, "n:o:")) != -1) {
            switch (c) {
            case 'n': n = atoi(optarg); break;
            case 'o': outfile = optarg; break;
            default: return cmd_usage_err;
            }
        }
    }

    if (!n || !outfile) { return cmd_usage_err; }

    uint8_t data[n];
    char hexdata[2*n+1];

    randombytes(data, sizeof data);
    to_hex(n, data, hexdata);
    hexdata[2*n] = '\n';

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
    fatal(outfd, "open");
    fatal(write(outfd, hexdata, sizeof hexdata), "write");
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
    {"box", cmd_box, "-p PUBLIC -s SECRET [-i IN] [-o OUT]"},
    {"box-open", cmd_box_open, "-p PUBLIC -s SECRET [-i IN] [-o OUT]"},
    {"box-beforenm", cmd_box_beforenm, "-p PUBLIC -s SECRET -k KEYFILE"},
    {"box-afternm", cmd_box_afternm, "-k KEYFILE [-i IN] [-o OUT]"},
    {"box-open-afternm", cmd_box_open_afternm, "-k KEYFILE [-i IN] [-o OUT]"},
    {"secretbox-key", cmd_secretbox_key, "-k KEYFILE"},
    {"secretbox", cmd_secretbox, "{-p | -k KEYFILE} [-i IN] [-o OUT]"},
    {"secretbox-open", cmd_secretbox_open, "{-p | -k KEYFILE} [-i IN] [-o OUT]"},
    {"hash", cmd_hash, "[-i IN] [-o OUT]"},
    {"random", cmd_random, "-n BYTES [-o OUT]"},
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

