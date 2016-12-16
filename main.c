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
#include "sqlite3.h"

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

void fatalfile(int err, const char *filename, const char *message) {
    if (err == -1) {
        fprintf(stderr, "%s: ", filename);
        perror(message);
        exit(1);
    }
}

#define load_file_initial_capacity (1<<14)
#define load_file_min_read (1<<14)

void *read_all(int fd, size_t *size) {
    size_t filled = 0;
    size_t capacity = load_file_initial_capacity;
    uint8_t *buffer = malloc(capacity + 1); // extra byte for \0

    for (;;) {
        while (capacity - filled < load_file_min_read) {
            capacity *= 2;
            buffer = realloc(buffer, capacity + 1); // extra byte for \0
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

    buffer[filled] = '\0';

    if (size != NULL) { *size = filled; }

    return buffer;
}

void read_exactly(int fd, size_t len, uint8_t buf[len]) {
    size_t filled = 0;

    for (;;) {
        int nr = read(fd, &buf[filled], len - filled);

        if (nr < 0) {
            perror("read exactly");
            exit(1);
        } else if (nr == 0 && filled < len) {
            fprintf(stderr, "Tried to fill buffer with %zu bytes but only got %zu\n", len, filled);
            exit(1);
        } else {
            filled += nr;

            if (filled == len) {
                return;
            }
        }
    }
}

#define fataldb(rc) if ((rc) != SQLITE_OK) { fprintf(stderr, "Line #%d: %s\n", __LINE__, sqlite3_errmsg(db)); sqlite3_close(db); exit(1); }

// databse is at the first valid location of the following:
//  - ${BOX_HOME}
//  - ${HOME}/.box-home
//  - .box-home
sqlite3 *use_db() {
    static sqlite3 *db = NULL;

    if (!db) {
        char *box_home = getenv("BOX_HOME");

        if (!box_home) {
            const char *home = getenv("HOME");

            if (!home) {
                box_home = ".box-home";
            } else {
                box_home = malloc(strlen(home) + strlen("/.box-home") + 1);
                strcpy(box_home, home);
                strcat(box_home, "/.box-home");
            }
        }

        if (sqlite3_open_v2(box_home, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL)) {
            fprintf(stderr, "Opening database: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(1);
        }

        {
            sqlite3_stmt *stmt;
            fataldb(sqlite3_prepare_v2(db, "pragma user_version;", -1, &stmt, NULL));
            if (sqlite3_step(stmt) != SQLITE_ROW) {
                fprintf(stderr, "Could not get user_version.\n");
                exit(1);
            }
            int version = sqlite3_column_int(stmt, 0);
            fataldb(sqlite3_finalize(stmt));

            if (version == 0) {
                fataldb(sqlite3_exec(db,
                    "CREATE TABLE identity ("
                    "   name text,"
                    "   boxpk blob,"
                    "   boxsk blob,"
                    "   signpk blob,"
                    "   signsk blob"
                    ");"
                    "CREATE TABLE contact ("
                    "   name text,"
                    "   boxpk blob,"
                    "   signpk blob"
                    ");"
                    "PRAGMA user_version = 1;",
                    NULL, NULL, NULL
                ));
            } else if (version > 1) {
                fprintf(stderr, "Unknown database version %d\n", version);
                exit(1);
            }
        }
    }

    return db;
}

void *load_all(const char *filename, size_t *size) {
    int fd = open(filename, O_RDONLY);
    fatalfile(fd, filename, "open");
    void *buf = read_all(fd, size);
    fatalfile(close(fd), filename, "close");
    return buf;
}

const char *bin_name;

__attribute__((noreturn)) void usage() {
    fprintf(stderr, "%s seal -password\n", bin_name);
    fprintf(stderr, "%s seal -password-file <file>\n", bin_name);
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

__attribute__((noreturn)) void cmd_new_identity(int argc, char *argv[argc]) {
    if (argc != 1) {
        usage();
    }

    const char *name = argv[0];

    uint8_t boxpk[crypto_box_PUBLICKEYBYTES];
    uint8_t boxsk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(boxpk, boxsk);

    uint8_t signpk[crypto_sign_PUBLICKEYBYTES];
    uint8_t signsk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(signpk, signsk);

    sqlite3 *db = use_db();

    sqlite3_stmt *stmt;

    fataldb(sqlite3_prepare_v2(
        db,
        "INSERT INTO identity (name, boxpk, boxsk, signpk, signsk) "
        "VALUES (?, ?, ?, ?, ?)",
        -1, &stmt, NULL
    ));

    fataldb(sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 2, boxpk, sizeof boxpk, SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 3, boxsk, sizeof boxsk, SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 4, signpk, sizeof signpk, SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 5, signsk, sizeof signsk, SQLITE_STATIC));

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    fataldb(sqlite3_finalize(stmt));

    char boxpkhex[1+2*sizeof boxpk];
    char signpkhex[1+2*sizeof signpk];

    sodium_bin2hex(boxpkhex, sizeof boxpkhex, boxpk, sizeof boxpk);
    sodium_bin2hex(signpkhex, sizeof signpkhex, signpk, sizeof signpk);

    printf("%s %s %s\n", name, boxpkhex, signpkhex);
    exit(0);
}

__attribute__((noreturn)) void cmd_add_contact(int argc, char *argv[argc]) {
    if (argc != 3) {
        usage();
    }

    const char *name = argv[0];
    const char *hexboxpk = argv[1];
    const char *hexsignpk = argv[2];

    if (strlen(hexboxpk)/2 != crypto_box_PUBLICKEYBYTES) {
        fprintf(stderr, "Invalid public key.\n");
        exit(1);
    }

    if (strlen(hexsignpk)/2 != crypto_sign_PUBLICKEYBYTES) {
        fprintf(stderr, "Invalid public key.\n");
        exit(1);
    }


    uint8_t boxpk[crypto_box_PUBLICKEYBYTES];
    uint8_t signpk[crypto_sign_PUBLICKEYBYTES];

    sodium_hex2bin(boxpk, sizeof boxpk, hexboxpk, strlen(hexboxpk), NULL, NULL, NULL);
    sodium_hex2bin(signpk, sizeof signpk, hexsignpk, strlen(hexsignpk), NULL, NULL, NULL);

    sqlite3 *db = use_db();

    sqlite3_stmt *stmt;

    fataldb(sqlite3_prepare_v2(
        db,
        "INSERT INTO contact (name, boxpk, signpk) "
        "VALUES (?, ?, ?)",
        -1, &stmt, NULL
    ));

    fataldb(sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 2, boxpk, sizeof boxpk, SQLITE_STATIC));
    fataldb(sqlite3_bind_blob(stmt, 3, signpk, sizeof signpk, SQLITE_STATIC));

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

    fataldb(sqlite3_finalize(stmt));
    exit(0);
}

__attribute__((noreturn)) void cmd_seal(int argc, char *argv[argc]) {
    bool use_password = false;
    char *to = NULL;
    char *from = NULL;
    char *password_file = NULL;

    while (*argv) {
        if (strcmp(*argv, "-password") == 0) {
            use_password = true;
            argv = &argv[1];
        } else if (strcmp(*argv, "-password-file") == 0) {
            password_file = argv[1];
            argv = &argv[2];
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

    if (use_password && !password_file && !to && !from) {
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
        void *m = read_all(STDIN_FILENO, &mlen);

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

        fprintf(stderr, "Writing out %zu bytes...\n", boxlen);
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (password_file && !use_password && !to && !from) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t passwordlen;
        char *password = load_all(password_file, &passwordlen);

        uint64_t opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
        size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
        int alg = crypto_pwhash_ALG_DEFAULT;

        if (isatty(STDIN_FILENO)) {
            fprintf(stderr, "Type your message below then press Ctrl+D on its own line to end it:\n");
        }

        size_t mlen;
        void *m = read_all(STDIN_FILENO, &mlen);

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
                password, passwordlen,
                box->salt,
                opslimit, memlimit, alg
       ), "crypto_pwhash");

        fprintf(stderr, "Encrypting message...\n");
        crypto_secretbox_easy(box->c, m, mlen, box->nonce, k);

        fprintf(stderr, "Writing out %zu bytes...\n", boxlen);
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (to && from && !use_password && !password_file) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = read_all(STDIN_FILENO, &mlen);

        size_t clen = crypto_box_MACBYTES + mlen;
        size_t boxlen = sizeof(box_from_to_header) + clen;
        box_from_to_header *box = malloc(boxlen);

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_FROM_TO);

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT boxpk FROM contact WHERE name = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_text(stmt, 1, to, strlen(to), SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Unknown contact %s\n", to);
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        const void *receiver_pk = sqlite3_column_blob(stmt, 0);
        memcpy(box->receiver_pk, receiver_pk, sizeof box->receiver_pk);
        fataldb(sqlite3_finalize(stmt));

        fataldb(sqlite3_prepare_v2(db, "SELECT boxpk, boxsk FROM identity WHERE name = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_text(stmt, 1, from, strlen(from), SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Unknown identity %s\n", to);
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        const void *sender_pk = sqlite3_column_blob(stmt, 0);
        const void *sender_sk = sqlite3_column_blob(stmt, 1);
        memcpy(box->sender_pk, sender_pk, sizeof box->sender_pk);

        randombytes_buf(box->nonce, sizeof box->nonce);
        
        fatal(crypto_box_easy(box->c, m, mlen, box->nonce, box->receiver_pk, sender_sk), "crypto_box_easy");
        fataldb(sqlite3_finalize(stmt));

        fprintf(stderr, "Writing out %zu bytes...\n", boxlen);
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (to && !from && !use_password && !password_file) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = read_all(STDIN_FILENO, &mlen);

        size_t clen = crypto_box_SEALBYTES + mlen;
        size_t boxlen = sizeof(box_to_header) + clen;
        box_to_header *box = malloc(boxlen);

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_TO);

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT boxpk FROM contact WHERE name = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_text(stmt, 1, to, strlen(to), SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Unknown contact %s\n", to);
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        const void *receiver_pk = sqlite3_column_blob(stmt, 0);
        memcpy(box->receiver_pk, receiver_pk, sizeof box->receiver_pk);
        fataldb(sqlite3_finalize(stmt));

        crypto_box_seal(box->c, m, mlen, box->receiver_pk);

        fprintf(stderr, "Writing out %zu bytes...\n", boxlen);
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else if (from && !to && !use_password && !password_file) {
        if (isatty(STDOUT_FILENO)) {
            fprintf(stderr, "Refusing to write box to tty.\n");
            exit(1);
        }

        size_t mlen;
        void *m = read_all(STDIN_FILENO, &mlen);

        size_t smlen = crypto_sign_BYTES + mlen;
        size_t boxlen = sizeof(box_from_header) + smlen;
        box_from_header *box = malloc(boxlen);

        save_uint64(box->header.len, boxlen);
        save_uint8(box->header.type, BOX_FROM);

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT signpk, signsk FROM identity WHERE name = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_text(stmt, 1, from, strlen(from), SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Unknown identity %s\n", to);
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        const void *sender_pk = sqlite3_column_blob(stmt, 0);
        const void *sender_sk = sqlite3_column_blob(stmt, 1);
        memcpy(box->sender_pk, sender_pk, sizeof box->sender_pk);

        crypto_sign(box->sm, NULL, m, mlen, sender_sk);
        fataldb(sqlite3_finalize(stmt));

        fprintf(stderr, "Writing out %zu bytes...\n", boxlen);
        fatal(write(STDOUT_FILENO, box, boxlen), "write");
        exit(0);
    } else {
        usage();
    }
}

__attribute__((noreturn)) void cmd_open(int argc, char *argv[argc]) {
    if (argc != 0) { usage(); }

    if (isatty(STDIN_FILENO)) {
        fprintf(stderr, "Refusing to read box from terminal.\n");
        exit(1);
    }

    box_common_header header;

    read_exactly(STDIN_FILENO, sizeof header, (uint8_t*)&header);

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

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT name, boxsk FROM identity WHERE boxpk = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_blob(stmt, 1, box->receiver_pk, sizeof box->receiver_pk, SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Box matches no known identity.\n");
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        //const unsigned char *name = sqlite3_column_text(stmt, 0);
        const void *receiver_sk = sqlite3_column_blob(stmt, 1);

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

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT name, boxsk FROM identity WHERE boxpk = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_blob(stmt, 1, box->receiver_pk, sizeof box->receiver_pk, SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Box matches no known identity.\n");
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        //const unsigned char *name = sqlite3_column_text(stmt, 0);
        const void *receiver_sk = sqlite3_column_blob(stmt, 1);

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

        sqlite3 *db = use_db();
        sqlite3_stmt *stmt;

        fataldb(sqlite3_prepare_v2(db, "SELECT name FROM contact WHERE signpk = ?;", -1, &stmt, NULL));
        fataldb(sqlite3_bind_blob(stmt, 1, box->sender_pk, sizeof box->sender_pk, SQLITE_STATIC));
        switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            fprintf(stderr, "Box matches no known identity.\n");
            exit(1);
        case SQLITE_ROW:
            break;
        default:
            fataldb(1);
        }

        // TODO: Should check size and columns
        //const unsigned char *name = sqlite3_column_text(stmt, 0);

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

int show_contact(void *arg, int ncols, char *cols[ncols], char *names[ncols]) {
    if (ncols != 3) {
        fprintf(stderr, "Wrong number of columns.\n");
        exit(1);
    }

    printf("%s %s %s\n", cols[0], cols[1], cols[2]);

    return 0;
}

__attribute__((noreturn)) void cmd_list_contacts(int argc, char *argv[argc]) {
    if (argc != 0) { usage(); }

    sqlite3 *db = use_db();

    char *errmsg;

    sqlite3_exec(db,
        "SELECT name, HEX(boxpk), HEX(signpk) FROM contact ORDER BY name;",
        show_contact, NULL, &errmsg
    );

    if (errmsg) {
        fprintf(stderr, "%s\n", errmsg);
        exit(1);
    }

    exit(0);
}

__attribute__((noreturn)) void cmd_list_identities(int argc, char *argv[argc]) {
    if (argc != 0) { usage(); }

    sqlite3 *db = use_db();

    char *errmsg;

    sqlite3_exec(db,
        "SELECT name, HEX(boxpk), HEX(signpk) FROM identity ORDER BY name;",
        show_contact, NULL, &errmsg
    );

    if (errmsg) {
        fprintf(stderr, "%s\n", errmsg);
        exit(1);
    }

    exit(0);
}

int main(int argc, char *argv[argc]) {
    bin_name = argv[0];

    if (argc >= 2 && strcmp(argv[1], "seal") == 0) {
        cmd_seal(argc - 2, &argv[2]);
    } else if (argc >= 2 && strcmp(argv[1], "open") == 0) {
        cmd_open(argc - 2, &argv[2]);
    } else if (argc >= 2 && strcmp(argv[1], "new-identity") == 0) {
        cmd_new_identity(argc - 2, &argv[2]);
    } else if (argc >= 2 && strcmp(argv[1], "add-contact") == 0) {
        cmd_add_contact(argc - 2, &argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "list-contacts") == 0) {
        cmd_list_contacts(argc - 2, &argv[2]);
    } else if (argc == 2 && strcmp(argv[1], "list-identities") == 0) {
        cmd_list_identities(argc - 2, &argv[2]);
    } else {
        usage();
    }

    return 2;
}

