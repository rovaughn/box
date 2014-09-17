#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "crypto_secretbox.h"
#include "crypto_hash_sha256.h"

#define BLOCKSIZE 1024

#if crypto_hash_sha256_BYTES < crypto_secretbox_KEYBYTES
  #error "The hash size is too small for the secretbox key"
#endif

int print_usage(void) {
  fprintf(stderr, "Usage: box 'password'\n");
  fprintf(stderr, "   or  unbox 'password'\n");
  return 1;
}

typedef struct {
  uint16_t len;
  uint8_t  nonce[crypto_secretbox_NONCEBYTES];
} block_header_t;

typedef struct {
  block_header_t header;
  union {
    uint8_t boxed_bytes[crypto_secretbox_ZEROBYTES + BLOCKSIZE];
    struct {
      uint8_t zero_bytes[crypto_secretbox_ZEROBYTES];
      uint8_t unboxed_bytes[BLOCKSIZE];
    };
  };
} block_t;

#define MIN_BLOCK_SIZE (2 + crypto_secretbox_NONCEBYTES + crypto_secretbox_ZEROBYTES)

void box_command(uint8_t *key) {
  block_t block;

  while (1) {
    memset(block.zero_bytes, 0, sizeof block.zero_bytes);

    size_t nread = fread(block.unboxed_bytes, 1, sizeof block.unboxed_bytes, stdin);

    if (nread == 0) {
      break;
    }

    block.header.len = crypto_secretbox_ZEROBYTES + nread;

    /* We'll see if the fact that the source and target buffers are the same
     * causes a problem. */
    crypto_secretbox(
      block.boxed_bytes, block.boxed_bytes, crypto_secretbox_ZEROBYTES + nread,
      block.header.nonce, key
    );

    fwrite(&block, sizeof block - (BLOCKSIZE - nread), 1, stdout);
  }
}

void unbox_command(uint8_t *key) {
  block_t block;

  while (1) {
    fread(&block.header, sizeof block.header, 1, stdin);

    if (ferror(stdin)) {
      break;
    }

    fread(block.boxed_bytes, block.header.len, 1, stdin);

    crypto_secretbox_open(
        block.boxed_bytes, block.boxed_bytes, block.header.len,
        block.header.nonce, key
    );

    /* Bad subtraction */
    fwrite(block.unboxed_bytes, block.header.len - crypto_secretbox_ZEROBYTES, 1, stdout);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return print_usage();
  }

  unsigned char *command  = (unsigned char*)argv[0],
                *password = (unsigned char*)argv[1];

  uint8_t key[crypto_hash_sha256_BYTES]; // Reserve hash_BYTES for the hash,
                                         // but only actually use the first
                                         // secretbox_BYTES.

  crypto_hash_sha256(key, password, strlen((char*)password));

  if (strcmp((char*)command, "./box") == 0) {
    box_command(key);
  } else if (strcmp((char*)command, "./unbox") == 0) {
    unbox_command(key);
  } else {
    return print_usage();
  }

  return 0;
}

