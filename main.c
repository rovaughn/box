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

void save_uint8(uint8_t b[1], uint64_t n) {
    b[0] = n;
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

uint8_t read_uint8(uint8_t b[1]) {
    return b[0];
}

void fatal(int err, const char *message) {
    if (err == -1) {
        perror(message);
        exit(1);
    }
}

void load_contact(const char *name, uint8_t pk[crypto_box_PUBLICKEYBYTES]) {
}

void load_identity(const char *name, uint8_t pk[crypto_box_PUBLICKEYBYTES], uint8_t sk[crypto_box_SECRETKEYBYTES]) {
}

void load_sign_identity(const char *name, uint8_t pk[crypto_sign_PUBLICKEYBYTES], uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
}

void load_identity_by_pk(uint8_t pk[crypto_sign_PUBLICKEYBYTES], uint8_t sk[crypto_sign_SECRETKEYBYTES]) {
}

#define load_file_initial_capacity (1<<14)
#define load_file_min_read (1<<14)

void *load_file(int fd, size_t *size) {
    size_t filled = 0;
    size_t capacity = load_file_initial_capacity;
    uint8_t *buffer = malloc(capacity);

    for (;;) {
        while (capacity - filled < load_file_min_read) {
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

const char *bin_name;

__attribute__((noreturn)) void usage() {
    fprintf(stderr, "%s seal -password\n", bin_name);
    fprintf(stderr, "%s seal -to <contact>\n", bin_name);
    fprintf(stderr, "%s seal -from <identity>\n", bin_name);
    fprintf(stderr, "%s seal -to <contact> -from <identity>\n", bin_name);
    fprintf(stderr, "%s open\n", bin_name);
    fprintf(stderr, "%s add-contact <name> <public-key>\n", bin_name);
    fprintf(stderr, "%s list-contacts\n", bin_name);
    fprintf(stderr, "%s new-identity <name>\n", bin_name);
    fprintf(stderr, "%s list-identities\n", bin_name);
    exit(1);
}

typedef enum {
    BOX_PASSWORD,
    BOX_TO,
    BOX_FROM,
    BOX_FROM_TO
} box_type;

typedef struct PACKED {
    uint8_t len[8];
    uint8_t type[1];
} box_common_header;

typedef struct PACKED {
    box_common_header header;
    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t opslimit[8];
    uint8_t memlimit[8];
    uint8_t alg[4];
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    uint8_t c[];
} box_password_header;

typedef struct PACKED {
    box_common_header header;
    uint8_t receiver_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t c[];
} box_to_header;

typedef struct PACKED {
    box_common_header header;
    uint8_t sender_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t sm[];
} box_from_header;

typedef struct PACKED {
    box_common_header header;
    uint8_t receiver_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sender_pk[crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];
    uint8_t c[];
} box_from_to_header;

__attribute__((noreturn)) void cmd_seal(int argc, char *argv[argc]) {
    bool use_password = false;
    char *to = NULL;
    char *from = NULL;

    while (*argv) {
        if (strcmp(*argv, "-password") == 0) {
            use_password = true;
            argv = &argv[1];
        } else if (strcmp(*argv, "-to") == 0) {
            to = argv[1];
            argv = &argv[2];
        } else if (strcmp(*argv, "-from") == 0) {
            from = argv[1];
            argv = &argv[2];
        } else {
            printf("failed here\n");
            usage();
        }
    }

    if (use_password && !to && !from) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        char *password;
        readpass(&password, "Password", "Confirm password", 1);

        uint64_t opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
        size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
        int alg = crypto_pwhash_ALG_DEFAULT;

        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Type your message below then press Ctrl+D on its own line to end it:\n");
        }

        size_t mlen;
        void *m = load_file(STDIN_FILENO, &mlen);

        size_t clen = crypto_secretbox_MACBYTES + mlen;
        size_t boxlen = sizeof(box_password_header) + clen;
        box_password_header *box = malloc(boxlen);

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_PASSWORD);
        randombytes_buf(box->salt, sizeof box->salt);
        save_uint64(box->opslimit, opslimit);
        save_uint64(box->memlimit, memlimit);
        save_uint32(box->alg, alg);
        randombytes_buf(box->nonce, sizeof box->nonce);

        uint8_t k[crypto_secretbox_KEYBYTES];

        fprintf(stderr, "Hashing password, this takes a few seconds...\n");
        fatal(crypto_pwhash(
                k, sizeof k,
                password, strlen(password),
                box->salt,
                opslimit, memlimit, alg
       ), "crypto_pwhash");

        fprintf(stderr, "Encrypting message...\n");
        crypto_secretbox_easy(box->c, m, mlen, box->nonce, k);

        fprintf(stderr, "Writing out...\n");
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (to && from && !use_password) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = load_file(STDIN_FILENO, &mlen);

        size_t clen = crypto_box_MACBYTES + mlen;
        size_t boxlen = sizeof(box_from_to_header) + clen;
        box_from_to_header *box = malloc(boxlen);

        uint8_t sender_sk[crypto_box_SECRETKEYBYTES];

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_FROM_TO);
        load_contact(to, box->receiver_pk);
        load_identity(from, box->sender_pk, sender_sk);
        randombytes_buf(box->nonce, sizeof box->nonce);
        
        fatal(crypto_box_easy(box->c, m, mlen, box->nonce, box->receiver_pk, sender_sk), "crypto_box_easy");

        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (to && !from && !use_password) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = load_file(STDIN_FILENO, &mlen);

        size_t clen = crypto_box_SEALBYTES + mlen;
        size_t boxlen = sizeof(box_to_header) + clen;
        box_to_header *box = malloc(boxlen);

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_TO);
        load_contact(to, box->receiver_pk);
        crypto_box_seal(box->c, m, mlen, box->receiver_pk);

        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (from && !to && !use_password) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = load_file(STDIN_FILENO, &mlen);

        size_t smlen = crypto_sign_BYTES + mlen;
        size_t boxlen = sizeof(box_from_header) + smlen;
        box_from_header *box = malloc(boxlen);

        uint8_t sender_sk[crypto_sign_SECRETKEYBYTES];

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_FROM);
        load_sign_identity(from, box->sender_pk, sender_sk);
        crypto_sign(box->sm, NULL, m, mlen, sender_sk);

        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else {
        usage();
    }
}

void read_exactly(int fd, size_t len, uint8_t buf[len]) {
    size_t filled = 0;

    for (;;) {
        int nr = read(fd, &buf[filled], len - filled);

        if (nr < 0) {
            perror("read exactly");
            exit(1);
        } else if (nr == 0) {
            if (filled != len) {
                fprintf(stderr, "Didn't read the expected number of bytes.\n");
                exit(1);
            }

            return;
        } else {
            filled += nr;
        }
    }
}

__attribute__((noreturn)) void cmd_open() {
    if (isatty(STDIN_FILENO)) {
        fprintf(stderr, "Refusing to read box from terminal.\n");
        exit(1);
    }

    box_common_header header;

    fatal(read(STDIN_FILENO, &header, sizeof header), "read header");

    uint8_t boxtype = read_uint8(header.type);
    size_t boxlen = read_uint64(header.len);

    uint8_t *raw_box = malloc(boxlen);

    read_exactly(STDIN_FILENO, boxlen - sizeof header, &raw_box[sizeof header]);

    if (boxtype == BOX_PASSWORD) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Refusing to read box from tty.\n");
            exit(1);
        }

        box_password_header *box = (box_password_header*)raw_box;

        char *password;
        readpass(&password, "Password", NULL, 1);

        uint8_t k[crypto_secretbox_KEYBYTES];

        fprintf(stderr, "Hashing password, this takes a few seconds...\n");
        fatal(crypto_pwhash(
            k, sizeof k,
            password, strlen(password),
            box->salt,
            read_uint64(box->opslimit), read_uint64(box->memlimit),
            read_uint32(box->alg)
        ), "crypto_pwhash");

        size_t clen = boxlen - sizeof(box_password_header);
        size_t mlen = clen - crypto_secretbox_MACBYTES;

        uint8_t *m = malloc(mlen);

        fprintf(stderr, "Decrypting box...\n");
        if (crypto_secretbox_open_easy(m, box->c, clen, box->nonce, k) == -1) {
            fprintf(stderr, "open failed!\n");
            exit(1);
        }

        fprintf(stderr, "Writing out...\n");
        fatal(write(STDOUT_FILENO, m, mlen), "write");
        exit(0);
    } else if (boxtype == BOX_FROM_TO) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Refusing to read box from tty.\n");
            exit(1);
        }

        box_from_to_header *box = (box_from_to_header*)raw_box;

        uint8_t receiver_sk[crypto_box_SECRETKEYBYTES];
        load_identity_by_pk(box->receiver_pk, receiver_sk);

        // TODO: Verify identity with contacts.
        size_t clen = boxlen - sizeof(box_from_to_header);
        size_t mlen = clen - crypto_box_MACBYTES;
        uint8_t *m = malloc(mlen);
        if (crypto_box_open_easy(m, box->c, clen, box->nonce, box->sender_pk, receiver_sk) == -1) {
            fprintf(stderr, "Open failed!\n");
            exit(1);
        }

        fatal(write(STDOUT_FILENO, m, mlen), "write");
        exit(0);
    } else if (boxtype == BOX_TO) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Refusing to read box from tty.\n");
            exit(1);
        }

        box_to_header *box = (box_to_header*)raw_box;

        uint8_t receiver_sk[crypto_box_SECRETKEYBYTES];
        load_identity_by_pk(box->receiver_pk, receiver_sk);

        size_t clen = boxlen - sizeof(box_to_header);
        size_t mlen = clen - crypto_box_SEALBYTES;
        uint8_t *m = malloc(mlen);
        if (crypto_box_seal_open(m, box->c, clen, box->receiver_pk, receiver_sk) == -1) {
            fprintf(stderr, "Open failed!\n");
            exit(1);
        }

        fatal(write(STDOUT_FILENO, m, mlen), "write");
        exit(0);
    } else if (boxtype == BOX_FROM) {
        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Refusing to read box from tty.\n");
            exit(1);
        }

        box_from_header *box = (box_from_header*)raw_box;

        size_t smlen = boxlen - sizeof(box_from_header);
        size_t mlen = smlen - crypto_sign_BYTES;
        uint8_t *m = malloc(mlen);

        // TODO: Verify identity with contacts.
        if (crypto_sign_open(m, NULL, box->sm, smlen, box->sender_pk) == -1) {
            fprintf(stderr, "Open failed!\n");
            exit(1);
        }

        fatal(write(STDOUT_FILENO, m, mlen), "write");
        exit(0);
    } else {
        fprintf(stderr, "Unknown box type: %d\n", boxtype);
        exit(1);
    }
}

int main(int argc, char *argv[argc]) {
    bin_name = argv[0];

    if (argc >= 2 && strcmp(argv[1], "seal") == 0) {
        cmd_seal(argc - 2, &argv[2]);
        return 0;
    } else if (argc == 2 && strcmp(argv[1], "open") == 0) {
        cmd_open(argc - 2, &argv[2]);
        return 0;
    /*} else if (argc == 2 && strcmp(argv[1], "add-contact") == 0) {
        cmd_add_contact(argc - 2, &argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "list-contacts") == 0) {
        cmd_list_contacts(argc - 2, &argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "new-identity") == 0) {
        cmd_new_identity(argc - 2, &argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "list-identities") == 0) {
        cmd_get_identity(argc - 2, &argv[2]);*/
    } else {
        usage();
    }

    return 2;
}

