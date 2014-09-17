#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "crypto_secretbox.h"
#include "crypto_hash_sha256.h"
#include "randombytes.h"

#define BLOCKSIZE 1024

#if crypto_hash_sha256_BYTES < crypto_secretbox_KEYBYTES
  #error "The hash size is too small for the secretbox key"
#endif

#define BOX_EXTRA (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)

int print_usage(void) {
  fprintf(stderr, "Usage: box 'password'\n");
  fprintf(stderr, "   or  unbox 'password'\n");
  return 1;
}

void box_command(uint8_t *key) {
  while (1) {
    struct {
      uint8_t zero[crypto_secretbox_ZEROBYTES],
              message[BLOCKSIZE];
    } message = {{0}};

    size_t nread = fread(message.message, 1, BLOCKSIZE, stdin);

    if (nread == 0) break;

    struct {
      uint16_t len;
      uint8_t  nonce[crypto_secretbox_NONCEBYTES];
      uint8_t  message[nread + BOX_EXTRA];
    } outblock;

    outblock.len = nread;
    randombytes(outblock.nonce, sizeof outblock.nonce);

    struct {
      uint8_t zero[crypto_secretbox_BOXZEROBYTES],
              message[nread + BOX_EXTRA];
    } boxed_message;

    crypto_secretbox((void*)&boxed_message, (void*)&message, sizeof boxed_message, outblock.nonce, key);
    memcpy(outblock.message, boxed_message.message, sizeof outblock.message);

    /* TODO check errors */
    fwrite(&outblock, sizeof outblock, 1, stdout);
  }
}

void unbox_command(uint8_t *key) {
  while (1) {
    struct {
      uint16_t len;
      uint8_t  nonce[crypto_secretbox_NONCEBYTES];
    } block_header;

    if (fread(&block_header, sizeof block_header, 1, stdin) == 0) {
      break;
    }

    struct {
      uint8_t zero[crypto_secretbox_BOXZEROBYTES],
              message[block_header.len + BOX_EXTRA];
    } boxed_message;

    memset(boxed_message.zero, 0, sizeof boxed_message.zero);

    struct {
      uint8_t zero[crypto_secretbox_ZEROBYTES],
              message[block_header.len];
    } message;

    if (fread(boxed_message.message, sizeof boxed_message.message, 1, stdin) == 0) {
      break;
    }

    if (crypto_secretbox_open((void*)&message, (void*)&boxed_message, sizeof boxed_message, block_header.nonce, key) == -1) {
      fprintf(stderr, "Block failed to decrypt.\n");
      continue;
    }

    fwrite(message.message, sizeof message.message, 1, stdout);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return print_usage();
  }

  char *command  = argv[0],
       *password = argv[1];

  uint8_t key[crypto_hash_sha256_BYTES]; // Reserve hash_BYTES for the hash,
                                         // but only actually use the first
                                         // secretbox_BYTES.

  crypto_hash_sha256(key, (unsigned char*)password, strlen(password));

  if (strcmp(command, "./box") == 0) {
    box_command(key);
  } else if (strcmp(command, "./unbox") == 0) {
    unbox_command(key);
  } else {
    return print_usage();
  }

  return 0;
}

