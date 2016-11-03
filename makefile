
CFLAGS := -Wall -Werror -Ilibnacl/include/amd64

all: .tested nacl

.tested: nacl.debug
	./test
	touch .tested

nacl.debug: main.c
	musl-gcc ${CFLAGS} -g main.c libnacl.a -o nacl.debug

nacl: main.c
	musl-gcc ${CFLAGS} -O3 -static -flto main.c libnacl.a -o nacl
	strip -s nacl

libnacl:
	./build-nacl

