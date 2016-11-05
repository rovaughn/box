#include <sodium.h>
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

#define crypto_scrypt_SALTBYTES 32

#define range(i, a, b) for (i = a; i < b; i++)
#define PACKED __attribute__((__packed__))

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

void save_uint64(uint8_t b[8], uint64_t n) {
    int i;
    range(i, 0, 8) { b[i] = (n>>(8*i))&0xff; }
}

void save_uint32(uint8_t b[4], uint64_t n) {
    int i;
    range(i, 0, 4) { b[i] = (n>>(8*i))&0xff; }
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

void fatal(int err, const char *message) {
    if (err == -1) {
        perror(message);
        exit(1);
    }
}

void fatalfile(int err, const char *file, const char *message) {
    if (err == -1) {
        fprintf(stderr, "%s: ", file);
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
    fatalfile(fd, path, "open");

    char buffer[strlen(label) + 1 + 2*len + 1];

    memcpy(buffer, label, strlen(label));
    buffer[strlen(label)] = ' ';
    to_hex(len, key, &buffer[strlen(label) + 1]);
    buffer[strlen(label) + 1 + 2*len] = '\n';

    fatalfile(write(fd, buffer, sizeof buffer), path, "write");
    fatalfile(close(fd), path, "close");
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

// TODO: do we really want to use labels for everything?
void load_key(const char *path, const char *expected_label, size_t len, uint8_t key[len]) {
    int fd = open(path, O_RDONLY);
    fatalfile(fd, path, "open");

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

typedef struct {
    const char *name;
    void (*func)(int argc, char *argv[argc]);
    const char *help_args;
} cmd_t;

char *usage_bin_name;
cmd_t *usage_current_cmd;

void usage() {
    fprintf(stderr, "%s %s %s\n",
            usage_bin_name, usage_current_cmd->name, usage_current_cmd->help_args);
    exit(1);
}

void cmd_box_keypair(int argc, char *argv[argc]) {
    char *pkfile = NULL;
    char *skfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "p:s:")) != -1) {
            switch (c) {
            case 'p': pkfile = optarg; break;
            case 's': skfile = optarg; break;
            default: usage();
            }
        }
    }

    if (!pkfile || !skfile) { usage(); }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk, sk);

    store_key(pkfile, public_mode, "public", sizeof pk, pk);
    store_key(skfile, secret_mode, "secret", sizeof sk, sk);

    sodium_memzero(sk, sizeof sk);
}

typedef struct PACKED {
    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t len[8];
    uint8_t m[];
} box_ciphertext;

void cmd_box(int argc, char *argv[argc]) {
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
            default: usage();
            }
        }
    }

    if (!pkfile || !skfile || !infile || !outfile) { usage(); }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(pkfile, "public", sizeof pk, pk);
    load_key(skfile, "secret", sizeof sk, sk);

    int infd = open(infile, O_RDONLY);
    fatalfile(infd, infile, "open");

    size_t mlen;
    void *m = load_file(infd, crypto_box_ZEROBYTES, &mlen);
    fatalfile(close(infd), infile, "close");

    size_t clen = sizeof(box_ciphertext) + mlen;
    box_ciphertext *c = malloc(clen);
    randombytes_buf(c->nonce, sizeof c->nonce);
    save_uint64(c->len, mlen);
    fatal(crypto_box(c->m, m, mlen, c->nonce, pk, sk), "crypto_box");

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
    fatalfile(outfd, outfile, "open");

    fatalfile(write(outfd, c, clen), outfile, "write");
    fatalfile(close(outfd), outfile, "close");
}

void cmd_box_open(int argc, char *argv[argc]) {
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
            default: usage();
            }
        }
    }

    if (!pkfile || !skfile || !infile || !outfile) { usage(); }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    load_key(pkfile, "public", sizeof pk, pk);
    load_key(skfile, "secret", sizeof sk, sk);

    int infd = open(infile, O_RDONLY);
    fatalfile(infd, infile, "open");

    size_t clen;
    box_ciphertext *c = load_file(infd, 0, &clen);
    fatalfile(close(infd), infile, "close");

    if (clen < sizeof *c) {
        fprintf(stderr, "Box is too small.\n");
        exit(1);
    }

    size_t mlen = clen - sizeof *c;
    uint8_t *m = malloc(mlen);

    if (crypto_box_open(m, c->m, mlen, c->nonce, pk, sk) == -1) {
        fprintf(stderr, "open failed!\n");
        exit(1);
    }

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
    fatalfile(outfd, outfile, "open");
    fatalfile(write(outfd, &m[crypto_box_ZEROBYTES], mlen - crypto_box_ZEROBYTES), outfile, "write");
    fatalfile(close(outfd), outfile, "close");
}

void cmd_secretbox_key(int argc, char *argv[argc]) {
    const char *keyfile = NULL;

    {
        char c;
        while ((c = getopt(argc, argv, "k:")) != -1) {
            switch (c) {
            case 'k': keyfile = optarg; break;
            default: usage();
            }
        }
    }

    if (!keyfile) { usage(); }

    uint8_t k[crypto_secretbox_KEYBYTES];

    randombytes_buf(k, sizeof k);
    store_key(keyfile, secret_mode, "secretbox", sizeof k, k);
}

typedef struct PACKED {
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t opslimit[8];
    uint8_t memlimit[8];
    uint8_t alg[4];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t len[8];
    uint8_t m[];
} secretbox_password_ciphertext;

typedef struct PACKED {
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t len[8];
    uint8_t m[];
} secretbox_ciphertext;

void cmd_secretbox(int argc, char *argv[argc]) {
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
            default: usage();
            }
        }
    }

    if ((use_password && keyfile) || (!use_password && !keyfile) || !infile || !outfile) {
        usage();
    }

    if (use_password) {
        char *password;
        readpass(&password, "Password", "Confirm password", 1);

        // there are better ways of deciding these, but these are what were used
        // by the scrypt utility on my laptop.
        // N must be power of 2 greater than 1
        // r * p < 2**30
        // buflen <= (2**32 - 1) * 32
        uint64_t opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
        size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
        int alg = crypto_pwhash_ALG_DEFAULT;

        int infd = open(infile, O_RDONLY);
        fatalfile(infd, infile, "open");

        size_t mlen;
        void *m = load_file(infd, crypto_secretbox_ZEROBYTES, &mlen);
        fatalfile(close(infd), infile, "close");

        size_t clen = sizeof(secretbox_password_ciphertext) + mlen;
        secretbox_password_ciphertext *c = malloc(clen);

        randombytes_buf(c->salt, sizeof c->salt);
        save_uint64(c->opslimit, opslimit);
        save_uint64(c->memlimit, memlimit);
        save_uint32(c->alg, alg);
        randombytes_buf(c->nonce, sizeof c->nonce);
        save_uint64(c->len, mlen);

        uint8_t k[crypto_secretbox_KEYBYTES];

        fatal(crypto_pwhash(
                k, sizeof k,
                password, strlen(password),
                c->salt,
                opslimit, memlimit, alg
       ), "crypto_pwhash");

        crypto_secretbox(c->m, m, mlen, c->nonce, k);

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
        fatalfile(outfd, outfile, "open");

        fatalfile(write(outfd, c, clen), outfile, "write");
        fatalfile(close(outfd), outfile, "close");
    } else {
        uint8_t k[crypto_secretbox_KEYBYTES];

        load_key(keyfile, "secretbox", sizeof k, k);

        int infd = open(infile, O_RDONLY);
        fatalfile(infd, infile, "open");

        size_t mlen;
        void *m = load_file(infd, crypto_secretbox_ZEROBYTES, &mlen);
        fatalfile(close(infd), infile, "close");

        size_t clen = sizeof(secretbox_ciphertext) + mlen;
        secretbox_ciphertext *c = malloc(clen);
        randombytes_buf(c->nonce, sizeof c->nonce);
        save_uint64(c->len, mlen);

        crypto_secretbox(c->m, m, mlen, c->nonce, k);

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, public_mode);
        fatalfile(outfd, outfile, "open");

        fatalfile(write(outfd, c, clen), outfile, "write");
        fatalfile(close(outfd), outfile, "close");
    }
}

void cmd_secretbox_open(int argc, char *argv[argc]) {
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
            default: usage();
            }
        }
    }

    if ((use_password && keyfile) || (!use_password && !keyfile) || !infile || !outfile) {
        usage();
    }

    if (use_password) {
        char *password;
        readpass(&password, "Password", "Confirm password", 1);

        int infd = open(infile, O_RDONLY);
        fatalfile(infd, infile, "open");

        size_t clen;
        secretbox_password_ciphertext *c = load_file(infd, 0, &clen);
        fatalfile(close(infd), infile, "close");

        if (clen < sizeof *c) {
            fprintf(stderr, "Too small.");
            exit(1);
        }

        size_t mlen = clen - sizeof(secretbox_password_ciphertext);
        uint8_t k[crypto_secretbox_KEYBYTES];

        if (crypto_pwhash(
                k, sizeof k,
                password, strlen(password),
                c->salt,
                read_uint64(c->opslimit), read_uint64(c->memlimit),
                read_uint32(c->alg)
            ) == -1) {
            fprintf(stderr, "scrypt failed\n");
            exit(1);
        }

        uint8_t *m = malloc(mlen);

        if (crypto_secretbox_open(m, c->m, mlen, c->nonce, k) == -1) {
            fprintf(stderr, "open failed!\n");
            exit(1);
        }

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
        fatalfile(outfd, outfile, "open");

        fatalfile(write(outfd, &m[crypto_secretbox_ZEROBYTES], mlen - crypto_secretbox_ZEROBYTES), outfile, "write");
        fatalfile(close(outfd), outfile, "close");
    } else {
        uint8_t k[crypto_secretbox_KEYBYTES];

        load_key(keyfile, "secretbox", sizeof k, k);

        int infd = open(infile, O_RDONLY);
        fatalfile(infd, infile, "open");

        size_t clen;
        secretbox_ciphertext *c = load_file(infd, 0, &clen);
        fatalfile(close(infd), infile, "close");

        if (clen < sizeof *c) {
            fprintf(stderr, "Ciphertext is lacking a nonce.\n");
            exit(1);
        }

        size_t mlen = clen - sizeof *c;
        uint8_t *m = malloc(mlen);

        if (crypto_secretbox_open(m, c->m, mlen, c->nonce, k) == -1) {
            fprintf(stderr, "open failed!\n");
            exit(1);
        }

        int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
        fatalfile(outfd, outfile, "open");

        fatalfile(write(outfd, &m[crypto_secretbox_ZEROBYTES], mlen - crypto_box_ZEROBYTES), outfile, "write");
        fatalfile(close(outfd), outfile, "close");
    }
}

void cmd_random(int argc, char *argv[argc]) {
    const char *outfile = "/dev/stdout";
    size_t n = 0;

    {
        char c;
        while ((c = getopt(argc, argv, "n:o:")) != -1) {
            switch (c) {
            case 'n': n = atoi(optarg); break;
            case 'o': outfile = optarg; break;
            default: usage();
            }
        }
    }

    if (!n || !outfile) { usage(); }

    uint8_t data[n];
    char hexdata[2*n+1];

    randombytes_buf(data, sizeof data);
    to_hex(n, data, hexdata);
    hexdata[2*n] = '\n';

    int outfd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, secret_mode);
    fatalfile(outfd, outfile, "open");
    fatalfile(write(outfd, hexdata, sizeof hexdata), outfile, "write");
    fatalfile(close(outfd), outfile, "close");
}

cmd_t cmds[] = {
    {"box-keypair", cmd_box_keypair, "-p PUBLICKEY -s SECRETKEY"},
    {"box", cmd_box, "-p PUBLICKEY -s SECRETKEY [-i IN] [-o OUT]"},
    {"box-open", cmd_box_open, "-p PUBLICKEY -s SECRETKEY [-i IN] [-o OUT]"},
    {"secretbox-key", cmd_secretbox_key, "-k KEYFILE"},
    {"secretbox", cmd_secretbox, "{-p | -k KEYFILE} [-i IN] [-o OUT]"},
    {"secretbox-open", cmd_secretbox_open, "{-p | -k KEYFILE} [-i IN] [-o OUT]"},
};

int main(int argc, char *argv[argc]) {
    size_t ncmds = sizeof cmds / sizeof cmds[0];

    if (argc >= 2) {
        int i;
        range(i, 0, ncmds) {
            if (strcmp(argv[1], cmds[i].name) == 0) {
                usage_bin_name = argv[0];
                usage_current_cmd = &cmds[i];
                cmds[i].func(argc - 1, &argv[1]);
                return 0;
            }
        }
    }

    fprintf(stderr, "Commands available:\n");
    int i;
    range(i, 0, ncmds) {
        fprintf(stderr, "%s %s %s\n", argv[0], cmds[i].name, cmds[i].help_args);
    }

    return 2;
}

