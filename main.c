#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include "crypto_secretbox.h"
#include "crypto_hash_sha256.h"
#include "randombytes.h"

#define BLOCKSIZE (2<<12)

#if crypto_hash_sha256_BYTES < crypto_secretbox_KEYBYTES
  #error "The hash size is too small for the secretbox key"
#endif

#define BOX_EXTRA (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)

int print_usage(void) {
  fprintf(stderr, "Usage: box 'password'\n");
  fprintf(stderr, "   or  unbox 'password'\n");
  return 1;
}

uint8_t *read_stdin(size_t initialZero, size_t initialFree, size_t *used) {
  size_t   bufferUsed = initialZero,
           bufferFree = initialFree;
  uint8_t *buffer     = malloc(bufferUsed + bufferFree);

  memset(buffer, 0, initialZero);

  for (;;) {
    size_t nread = fread(&buffer[bufferUsed], 1, bufferFree, stdin);

    if (nread < bufferFree) {
      bufferUsed += nread;
      buffer      = realloc(buffer, bufferUsed);
      goto done;
    } else {
      bufferUsed += bufferFree;
      bufferFree  = bufferUsed / 2;
      buffer      = realloc(buffer, bufferUsed + bufferFree);
    }
  }

done:
  *used = bufferUsed;

  return buffer;
}

void showb(uint8_t *ptr, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    fprintf(stderr, "%02x ", ptr[i]);
  }
  fprintf(stderr, "\n");
}

void box_command(uint8_t *key) {
  size_t   bufferUsed;
  uint8_t *buffer = read_stdin(crypto_secretbox_ZEROBYTES, 1024, &bufferUsed),
           nonce[crypto_secretbox_NONCEBYTES];

  struct {
    union {
      struct {
        uint8_t padding[crypto_secretbox_ZEROBYTES - crypto_secretbox_NONCEBYTES],
                nonce[crypto_secretbox_NONCEBYTES];
      };
      uint8_t zero[crypto_secretbox_ZEROBYTES];
    };
    uint8_t message[bufferUsed];
  } outblock;

  randombytes(nonce, sizeof nonce);
  showb(nonce, sizeof nonce);
  showb(buffer, bufferUsed);

  crypto_secretbox(
    (void*)outblock.zero, (void*)buffer,
    bufferUsed, nonce, key
  );

  memcpy(outblock.nonce, nonce, sizeof nonce);

  showb((void*)&outblock, sizeof outblock);

  /* TODO check errors */
  fwrite(outblock.nonce, sizeof outblock - sizeof outblock.padding, 1, stdout);

  free(buffer);
}

void unbox_command(uint8_t *key) {
  size_t bufferUsed;
  union {
    struct {
      uint8_t nonce[crypto_secretbox_NONCEBYTES],
              ciphertext[bufferUsed - crypto_secretbox_NONCEBYTES];
    };
    struct {
      uint8_t boxpad[crypto_secretbox_NONCEBYTES - crypto_secretbox_BOXZEROBYTES],
              boxzero[crypto_secretbox_BOXZEROBYTES];
    };
  } *inblock = (void*)read_stdin(0, 1024, &bufferUsed);

  if (bufferUsed < crypto_secretbox_NONCEBYTES) {
    fprintf(stderr, "The message is not long enough to contain a nonce, and is thus invalid.\n");
    exit(1);
  }

  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  struct {
    uint8_t zero[crypto_secretbox_ZEROBYTES],
            plaintext[bufferUsed - crypto_secretbox_NONCEBYTES - BOX_EXTRA];
  } out;

  memcpy(nonce, inblock->nonce, sizeof nonce);
  memset(inblock->boxzero, 0, sizeof inblock->boxzero);
  crypto_secretbox_open(out.zero, inblock->boxzero, sizeof out, nonce, key);

  fwrite(out.plaintext, sizeof out.plaintext, 1, stdout);

  free(inblock);
}

int main(int argc, char **argv) {
  if (argc != 1) {
    return print_usage();
  }

  char *command  = argv[0],
       *password = getpass("Password: ");

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

