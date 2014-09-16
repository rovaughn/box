#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "crypto_secretbox.h"
#include "crypto_hash_sha256.h"

#define BLOCKSIZE 1024

#if crypto_hash_sha256_BYTES < crypto_secretbox_KEYBYTES
  #error "The hash size is too small for the secretbox key"
#endif

/* Usage:
 *  box 'password'
 *  unbox 'password'
 */

int print_usage(void) {
  fprintf(stderr, "Usage: box 'password'\n");
  fprintf(stderr, "   or  unbox 'password'\n");
  return 1;
}

void box_command(uint8_t *key) {
  printf("Box\n");
}

void unbox_command(uint8_t *key) {
  printf("Unbox\n");
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

  crypto_hash_sha256(key, password, strlen(password));

  if (strcmp(command, "./box") == 0) {
    box_command(key);
  } else if (strcmp(command, "unbox") == 0) {
    unbox_command(key);
  } else {
    return print_usage();
  }

  return 0;
}

