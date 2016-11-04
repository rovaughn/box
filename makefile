
CFLAGS := -Wall -Werror -I/usr/local/include
LDFLAGS := -lsodium -L/usr/local/lib
SRC := main.c readpass.c insecure_memzero.c warnp.c

all: .tested nacl

libsodium-1.0.11.tar.gz:
	wget 'https://download.libsodium.org/libsodium/releases/libsodium-1.0.11.tar.gz'

libsodium-1.0.11: libsodium-1.0.11.tar.gz:
	tar xaf libsodium-1.0.11.tar.gz

.libsodium: libsodium-1.0.11
	cd libsodium-1.0.11
	./configure
	make
	sudo make install
	touch .libsodium

.tested: nacl.debug build-nacl test
	shellcheck build-nacl test
	./test
	touch .tested

nacl.debug: main.c
	gcc ${CFLAGS} -g ${SRC} ${LDFLAGS} -o nacl.debug

nacl: main.c
	gcc ${CFLAGS} -O3 -static -flto ${SRC} ${LDFLAGS} -o nacl
	strip -s nacl

libnacl:
	./build-nacl

