
CFLAGS := -Wall -Werror -Ilibnacl/include/amd64

.PHONY: tested

tested: nacl.debug
	./test

nacl.debug: main.c
	gcc ${CFLAGS} -g main.c libnacl.a -o nacl.debug

nacl: main.c
	gcc ${CFLAGS} -O3 -s -flto main.c libnacl.a -o nacl

libnacl:
	./build-nacl

