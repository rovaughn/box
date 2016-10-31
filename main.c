#include <crypto_box.h>
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

void fatal(int err, const char *message) {
    if (err == -1) {
        perror(message);
        exit(1);
    }
}

void store_secret_key(const char *path, size_t len, const uint8_t key[len]) {
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, S_IRUSR);

    fatal(fd, "open");

    static const char label[] = "secret ";
    char buffer[sizeof label + 2*len + 1];

    memcpy(buffer, label, sizeof label);
    to_hex(len, key, &buffer[sizeof label]);
    buffer[sizeof label + 2*len] = '\n';

    fatal(write(fd, buffer, sizeof buffer), "write");
    fatal(close(fd), "close");
}

void store_public_key(const char *path, size_t len, const uint8_t key[len]) {
    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, S_IRUSR|S_IRGRP|S_IROTH);

    fatal(fd, "open");

    static const char label[] = "public ";
    char buffer[sizeof label + 2*len + 1];

    memcpy(buffer, label, sizeof label);
    to_hex(len, key, &buffer[sizeof label]);
    buffer[sizeof buffer - 1] = '\n';

    fatal(write(fd, buffer, sizeof buffer), "write");
    fatal(close(fd), "close");
}

void cmd_box_keypair(int argc, char *argv[argc]) {
    int c;

    char *public_keyfile = NULL;
    char *secret_keyfile = NULL;

    while ((c = getopt(argc, argv, "p:s:")) != -1) {
        switch (c) {
        case 'p':
            public_keyfile = optarg;
            break;
        case 's':
            secret_keyfile = optarg;
            break;
        case '?':
            if (optopt == 'p') {
                fprintf(stderr, "Option -p requires an argument.\n");
            } else if (optopt == 's') {
                fprintf(stderr, "Option -s requires an argument.\n");
            } else {
                fprintf(stderr, "Unknown option -%c.\n", optopt);
            }
        default:
            abort();
        }
    }

    if (!public_keyfile) {
        fprintf(stderr, "Public keyfile required.\n");
        exit(1);
    }

    if (!secret_keyfile) {
        fprintf(stderr, "Secret keyfile required.\n");
        exit(1);
    }

    uint8_t pk[crypto_box_PUBLICKEYBYTES];
    uint8_t sk[crypto_box_SECRETKEYBYTES];

    crypto_box_keypair(pk, sk);

    store_public_key(public_keyfile, sizeof pk, pk);
    store_secret_key(secret_keyfile, sizeof sk, sk);

    memset_s(sk, 0, sizeof sk);
}

void cmd_help(int argc, char *argv[argc]) {
    fprintf(stderr, "nacl box keypair\n");
    exit(1);
}

int main(int argc, char *argv[argc]) {
    if (argc >= 3 && strcmp(argv[1], "box") == 0 && strcmp(argv[2], "keypair") == 0) {
        cmd_box_keypair(argc - 2, &argv[2]);
    } else {
        cmd_help(argc, argv);
    }

    return 0;
}

// void print_usage(void) {
//   fprintf(stderr, "Usage: box 'password'\n");
//   fprintf(stderr, "   or: unbox 'password'\n");
// }
// 
// /* Read a *FILE until EOF into a malloc'd buffer.
//  *  file        - The file to read from.
//  *  initialZero - Reserves this many bytes at the beginning of the buffer
//  *                and zeroes all of them.
//  *  initialFree - Amount of free space to initialize the buffer.  The value
//  *                doesn't really matter.
//  *  used        - The resulting size of the buffer, including the initialZero
//  *                bytes, is stored in this pointer.
//  *  Returns the buffer.
//  */
// uint8_t *read_file(FILE *file, size_t initialZero, size_t initialFree, size_t *used) {
//   size_t   bufferUsed = initialZero,
//            bufferFree = initialFree;
//   uint8_t *buffer     = malloc(bufferUsed + bufferFree);
// 
//   if (buffer == NULL) {
//     fprintf(stderr, "Out of memory\n");
//     exit(1);
//   }
// 
//   memset(buffer, 0, initialZero);
// 
//   for (;;) {
//     size_t nread = fread(&buffer[bufferUsed], 1, bufferFree, file);
// 
//     if (nread < bufferFree) {
//       bufferUsed += nread;
//       goto done;
//     } else {
//       bufferUsed += bufferFree;
//       bufferFree  = bufferUsed / 2;
//       buffer      = realloc(buffer, bufferUsed + bufferFree);
// 
//       if (buffer == NULL) {
//         fprintf(stderr, "Out of memory\n");
//         exit(1);
//       }
//     }
//   }
// 
// done:
//   *used = bufferUsed;
// 
//   return buffer;
// }
// 
// /* For debugging.  Prints n bytes from address ptr in hex. */
// void showb(uint8_t *ptr, size_t n) {
//   size_t i;
//   for (i = 0; i < n; ++i) {
//     fprintf(stderr, "%02x", ptr[i]);
//   }
//   fprintf(stderr, "\n");
// }
// 
// /* Implements the box command.
//  *  key - Key used to encrypt the data.
//  */
// void box_command(uint8_t *key) {
//   size_t   bufferUsed;
//   uint8_t *buffer = read_file(stdin, crypto_secretbox_ZEROBYTES, 1024, &bufferUsed),
//            nonce[crypto_secretbox_NONCEBYTES];
// 
//   /* This is the block that will be emitted.
//    * Because of nacl's design, the buffer that we write the ciphertext into will
//    * include BOXZEROBYTES (16) bytes that will be zero'd out.  Thus, we write
//    * the ciphertext starting at the "Zero bytes" mark, then overwrite it with
//    * the nonce, which is NONCEBYTES (24) bytes long.
//    *
//    * Nonce     Ciphertext
//    * [        ][                                ]
//    * +------------------------------------------+
//    * |   |     |                                |
//    * +------------------------------------------+
//    *     [    ] 
//    *     Zero bytes
//    */
//   struct {
//     union {
//       uint8_t nonce[crypto_secretbox_NONCEBYTES];
//       struct {
//         uint8_t padding[crypto_secretbox_NONCEBYTES -
//                         crypto_secretbox_BOXZEROBYTES],
//                 zero[crypto_secretbox_BOXZEROBYTES];
//       };
//     };
//     uint8_t ciphertext[bufferUsed - crypto_secretbox_ZEROBYTES + BOX_EXTRA];
//   } *outblock = malloc(sizeof *outblock);
// 
//   randombytes(nonce, sizeof nonce);
// 
//   crypto_secretbox(
//     (void*)outblock->zero, (void*)buffer,
//     bufferUsed, nonce, key
//   );
// 
//   memcpy(outblock->nonce, nonce, sizeof nonce);
// 
//   if (fwrite(outblock->nonce, sizeof *outblock, 1, stdout) == 0) {
//     perror("fwrite");
//     exit(1);
//   }
// 
//   free(outblock);
//   free(buffer);
// }
// 
// void unbox_command(uint8_t *key) {
//   size_t bufferUsed;
//   void *buffer = read_file(stdin, 0, 1024, &bufferUsed);
// 
//   /* This is the block that we're going to read in.
//    * The nonce is NONCEBYTES (24) bytes long, followed by an arbitrary length
//    * ciphertext.  When we decrypt, we need BOXZEROBYTES (16) bytes before the
//    * ciphertext to be zero'd.
//    *
//    * [ Nonce  ][ Ciphertext                 ]
//    * +--------------------------------------+
//    * |   |     |                            |
//    * +--------------------------------------+
//    *     [Zero]
//    *
//    *     [ Zero    ]
//    *     +----------------------------------+
//    *     |          |                       |
//    *     +----------------------------------+
//    *                [ Plaintext            ]
//    */
//   struct {
//     union {
//       uint8_t nonce[crypto_secretbox_NONCEBYTES];
//       struct {
//         uint8_t padding[crypto_secretbox_NONCEBYTES -
//                         crypto_secretbox_BOXZEROBYTES],
//                 zero[crypto_secretbox_BOXZEROBYTES];
//       };
//     };
//     uint8_t ciphertext[bufferUsed - crypto_secretbox_NONCEBYTES];
//   } *inblock = buffer;
// 
//   if (bufferUsed < crypto_secretbox_NONCEBYTES + BOX_EXTRA) {
//     fprintf(stderr, "The message is not long enough to contain a nonce and code, and is thus invalid.\n");
//     exit(1);
//   }
// 
//   uint8_t nonce[crypto_secretbox_NONCEBYTES];
//   struct {
//     uint8_t zero[crypto_secretbox_ZEROBYTES],
//             plaintext[bufferUsed - crypto_secretbox_NONCEBYTES - BOX_EXTRA];
//   } *out = malloc(sizeof *out);
// 
//   memcpy(nonce, inblock->nonce, sizeof nonce);
//   memset(inblock->zero, 0, sizeof inblock->zero);
// 
//   if (crypto_secretbox_open(out->zero, inblock->zero, sizeof *out, nonce, key) == -1) {
//     fprintf(stderr, "Couldn't unbox.\n");
//     exit(1);
//   }
// 
//   if (fwrite(out->plaintext, sizeof out->plaintext, 1, stdout) == 0) {
//     perror("fwrite");
//     exit(1);
//   }
// 
//   free(out);
//   free(inblock);
// }
// 
// void generate_key_command(void) {
//   uint8_t key[crypto_secretbox_KEYBYTES];
// 
//   randombytes(key, sizeof key);
// 
//   int i;
//   for (i = 0; i < sizeof key; ++i) {
//     printf("%02x", key[i]);
//   }
// 
//   printf("\n");
// }
// 
// #if crypto_hash_sha256_BYTES != crypto_secretbox_KEYBYTES
//   #error "The hash size is too small for the secretbox key"
// #endif
// 
// void get_key(uint8_t *key, int argc, char **argv) {
//   if (argc == 1) {
//     char *password = getpass("Password: ");
// 
//     if (password == NULL) {
//       perror("getpass");
//       exit(1);
//     }
// 
//     crypto_hash_sha256(key, (unsigned char*)password, strlen(password));
//   } else if (argc == 2) {
//     char *keyfileName = argv[1];
//     FILE *keyfile = fopen(keyfileName, "rb");
// 
//     if (keyfile == NULL) {
//       fprintf(stderr, "Opening keyfile '%s': ", keyfileName);
//       perror("");
//       exit(1);
//     }
// 
//     size_t keyfileContentsLength;
//     uint8_t *keyfileContents = read_file(keyfile, 0, 64, &keyfileContentsLength);
//     
//     if (fclose(keyfile) == EOF) {
//       perror("fclose keyfile");
//       exit(1);
//     }
// 
//     crypto_hash_sha256(key, keyfileContents, keyfileContentsLength);
//   } else {
//     print_usage();
//     exit(1);
//   }
// }
// 
