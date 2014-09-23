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
  fprintf(stderr, "   or: unbox 'password'\n");
  return 1;
}

/* Read stdin until EOF into a malloc'd buffer.
 *  initialZero - Reserves this many bytes at the beginning of the buffer
 *                and zeroes all of them.
 *  initialFree - Amount of free space to initialize the buffer.  The value
 *                doesn't really matter.
 *  used        - The resulting size of the buffer, including the initialZero
 *                bytes, is stored in this pointer.
 *  Returns the buffer.
 */
uint8_t *read_stdin(size_t initialZero, size_t initialFree, size_t *used) {
  size_t   bufferUsed = initialZero,
           bufferFree = initialFree;
  uint8_t *buffer     = malloc(bufferUsed + bufferFree);

  fprintf(stderr, "Allocated buffer of size %zu\n", bufferUsed + bufferFree);

  if (buffer == NULL) {
    fprintf(stderr, "Out of memory\n");
    exit(1);
  }

  memset(buffer, 0, initialZero);

  for (;;) {
    size_t nread = fread(&buffer[bufferUsed], 1, bufferFree, stdin);

    fprintf(stderr, "Currently %zu bytes used in buffer; read %zu out of %zu free\n", bufferUsed, nread, bufferFree);

    if (nread < bufferFree) {
      bufferUsed += nread;

      fprintf(stderr, "realloc'ing buffer to %zu bytes\n", bufferUsed);
      /*buffer      = realloc(buffer, bufferUsed);

      if (buffer == NULL) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
      }*/

      goto done;
    } else {
      bufferUsed += bufferFree;
      bufferFree  = bufferUsed / 2;
      buffer      = realloc(buffer, bufferUsed + bufferFree);

      if (buffer == NULL) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
      }
    }
  }

done:
  *used = bufferUsed;

  return buffer;
}

/* For debugging.  Prints n bytes from address ptr in hex. */
void showb(uint8_t *ptr, size_t n) {
  size_t i;
  for (i = 0; i < n; ++i) {
    fprintf(stderr, "%02x", ptr[i]);
  }
  fprintf(stderr, "\n");
}

/* Implements the box command.
 *  key - Key used to encrypt the data.
 */
void box_command(uint8_t *key) {
  size_t   bufferUsed;
  uint8_t *buffer = read_stdin(crypto_secretbox_ZEROBYTES, 1024, &bufferUsed),
           nonce[crypto_secretbox_NONCEBYTES];

  /* This is the block that will be emitted.
   * Because of nacl's design, the buffer that we write the ciphertext into will
   * include BOXZEROBYTES (16) bytes that will be zero'd out.  Thus, we write
   * the ciphertext starting at the "Zero bytes" mark, then overwrite it with
   * the nonce, which is NONCEBYTES (24) bytes long.
   *
   * Nonce     Ciphertext
   * [        ][                                ]
   * +------------------------------------------+
   * |   |     |                                |
   * +------------------------------------------+
   *     [    ] 
   *     Zero bytes
   */
  struct {
    union {
      uint8_t nonce[crypto_secretbox_NONCEBYTES];
      struct {
        uint8_t padding[crypto_secretbox_NONCEBYTES -
                        crypto_secretbox_BOXZEROBYTES],
                zero[crypto_secretbox_BOXZEROBYTES];
      };
    };
    uint8_t ciphertext[bufferUsed];
  } outblock;

  randombytes(nonce, sizeof nonce);

  crypto_secretbox(
    (void*)outblock.zero, (void*)buffer,
    bufferUsed, nonce, key
  );

  fprintf(stderr, "Outblock: ");
  showb(outblock.nonce, sizeof outblock.nonce + sizeof outblock.ciphertext);

  memcpy(outblock.nonce, nonce, sizeof nonce);

  fprintf(stderr, "Outblock: ");
  showb(outblock.nonce, sizeof outblock.nonce + sizeof outblock.ciphertext);

  /* TODO check errors */
  fwrite(outblock.nonce, sizeof outblock - sizeof outblock.padding, 1, stdout);

  free(buffer);
}

void unbox_command(uint8_t *key) {
  size_t bufferUsed;

  /* This is the block that we're going to read in.
   * The nonce is NONCEBYTES (24) bytes long, followed by an arbitrary length
   * ciphertext.  When we decrypt, we need BOXZEROBYTES (16) bytes before the
   * ciphertext to be zero'd.
   *
   * Nonce     Ciphertext
   * [        ][                            ]
   * +--------------------------------------+
   * |   |     |                            |
   * +--------------------------------------+
   *     [    ] 
   *     Zero bytes
   */
  struct {
    union {
      uint8_t nonce[crypto_secretbox_NONCEBYTES];
      struct {
        uint8_t padding[crypto_secretbox_NONCEBYTES -
                        crypto_secretbox_BOXZEROBYTES],
                zero[crypto_secretbox_BOXZEROBYTES];
      };
    };
    uint8_t ciphertext[];
  } *inblock = (void*)read_stdin(0, 1024, &bufferUsed);

  if (bufferUsed < crypto_secretbox_NONCEBYTES) {
    fprintf(stderr, "The message is not long enough to contain a nonce, and is thus invalid.\n");
    exit(1);
  }

  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  struct {
    uint8_t zero[crypto_secretbox_ZEROBYTES],
            plaintext[bufferUsed - crypto_secretbox_NONCEBYTES + crypto_secretbox_BOXZEROBYTES];
  } out;

  memcpy(nonce, inblock->nonce, sizeof nonce);
  memset(inblock->zero, 0, sizeof inblock->zero);

  if (crypto_secretbox_open(out.zero, inblock->zero, sizeof out, nonce, key) == -1) {
    fprintf(stderr, "Couldn't unbox.\n");
    exit(1);
  }

  fwrite(out.plaintext, sizeof out.plaintext, 1, stdout);

  free(inblock);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return print_usage();
  }

  char *command  = argv[0],
       *password = argv[1];
  //   *password = getpass("Password: ");

  uint8_t key[crypto_hash_sha256_BYTES]; // Reserve hash_BYTES for the hash,
                                         // but only actually use the first
                                         // secretbox_BYTES.

  crypto_hash_sha256(key, (unsigned char*)password, strlen(password));

  if (strcmp((char*)command, "./box") == 0) {
    box_command(key);
  } else if (strcmp((char*)command, "./unbox") == 0) {
    unbox_command(key);
  } else {
    return print_usage();
  }

  return 0;
}

