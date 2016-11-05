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

#define range(i, a, b) for (i = a; i < b; i++)
#define PACKED __attribute__((__packed__))

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
    range(i, 0, 8) { n |= b[i] << (8*i); }
    return n;
}

uint32_t read_uint32(uint8_t b[4]) {
    uint64_t n = 0;
    int i;
    range(i, 0, 4) { n |= b[i] << (8*i); }
    return n;
}

void fatal(int err, const char *message) {
    if (err == -1) {
        perror(message);
        exit(1);
    }
}

void *load_file(int fd, size_t zero_padding, size_t *size) {
    static const size_t initial_capacity = 1<<14;
    static const size_t min_read = 1<<14;

    size_t filled = zero_padding;
    size_t capacity = zero_padding + initial_capacity;
    uint8_t *buffer = malloc(capacity);
    memset(buffer, 0, zero_padding);

    for (;;) {
        while (capacity - filled < min_read) {
            capacity *= 2;
            buffer = realloc(buffer, capacity);
        }

        ssize_t nr = read(fd, &buffer[filled], capacity - filled);

        if (nr == -1) {
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

const mode_t public_mode = S_IRUSR|S_IRGRP|S_IROTH;
const mode_t secret_mode = S_IRUSR;

typedef struct PACKED {
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t opslimit[8];
    uint8_t memlimit[8];
    uint8_t alg[4];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t len[8];
    uint8_t m[];
} box_header;

__attribute__((noreturn)) void cmd_seal() {
    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, "Refusing to write box to terminal.\n");
        exit(1);
    }

    char *password;
    readpass(&password, "Password", "Confirm password", 1);

    uint64_t opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
    int alg = crypto_pwhash_ALG_DEFAULT;

    size_t mlen;
    void *m = load_file(STDIN_FILENO, crypto_secretbox_ZEROBYTES, &mlen);

    size_t clen = sizeof(box_header) + mlen;
    box_header *c = malloc(clen);

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

    fatal(write(STDOUT_FILENO, c, clen), "write");

    exit(0);
}

__attribute__((noreturn)) void cmd_open() {
    if (isatty(STDIN_FILENO)) {
        fprintf(stderr, "Refusing to read box from terminal.\n");
        exit(1);
    }

    char *password;
    readpass(&password, "Password", NULL, 1);

    size_t clen;
    box_header *c = load_file(STDIN_FILENO, 0, &clen);

    if (clen < sizeof *c) {
        fprintf(stderr, "Too small.");
        exit(1);
    }

    size_t mlen = clen - sizeof(box_header);
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

    fatal(write(
        STDOUT_FILENO,
        &m[crypto_secretbox_ZEROBYTES],
        mlen - crypto_secretbox_ZEROBYTES
    ), "write");

    exit(0);
}

const char *bin_name;

__attribute__((noreturn)) void usage() {
    fprintf(stderr, "%s seal <message >ciphertext\n", bin_name);
    fprintf(stderr, "%s open <ciphertext >message\n", bin_name);
    exit(1);
}

int main(int argc, char *argv[argc]) {
    bin_name = argv[0];

    if (argc == 2 && strcmp(argv[1], "seal") == 0) {
        cmd_seal();
        return 0;
    } else if (argc == 2 && strcmp(argv[1], "open") == 0) {
        cmd_open();
        return 0;
    } else {
        usage();
    }

    return 2;
}

