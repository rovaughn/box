
CFLAGS := -Wall -Werror -Ilibnacl/include/amd64 

test: nacl
	rm -f p s
	valgrind -q ./nacl.debug box keypair -p p -s s

nacl.debug: main.c
	gcc ${CFLAGS} -g main.c libnacl.a -o nacl.debug

nacl: main.c
	gcc ${CFLAGS} -O3 -s -flto main.c libnacl.a -o nacl

libnacl:
	./build-nacl

