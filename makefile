
CFLAGS := -Wall -Werror -Ilibnacl/include/amd64 \
	      -Iscrypt/lib/crypto
SRC := main.c readpass.c insecure_memzero.c warnp.c libnacl.a \
	   scrypt/lib/crypto/crypto_scrypt.o scrypt/libcperciva/alg/sha256.o \
	   scrypt/libcperciva/cpusupport/cpusupport_x86_sse2.o \
	   scrypt/lib/crypto/crypto_scrypt_smix.o \
	   scrypt/lib/crypto/libscrypt_sse2_a-crypto_scrypt_smix_sse2.o

all: .tested nacl

.tested: nacl.debug build-nacl test
	shellcheck build-nacl test
	./test
	touch .tested

nacl.debug: main.c
	gcc ${CFLAGS} -g ${SRC} -o nacl.debug

nacl: main.c
	musl-gcc ${CFLAGS} -O3 -static -flto ${SRC} -o nacl
	strip -s nacl

libnacl:
	./build-nacl

