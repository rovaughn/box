
CFLAGS := -Wall -Werror -Ilibnacl/include/amd64 

test: nacl.debug
	rm -f p1 p2 s1 s2 m c mout
	valgrind -q ./nacl.debug box keypair -p p1 -s s1
	valgrind -q ./nacl.debug box keypair -p p2 -s s2
	echo 'attack at dawn' >m
	valgrind -q ./nacl.debug box make -p p2 -s s1 -m m -c c
	valgrind -q ./nacl.debug box open -p p1 -s s2 -m mout -c c
	cat mout

# p1 s1 p1 s1 works
# p2 s1 p2 s1 works
# p1 s2 p1 s2 works
# p2 s2 p2 s2 works

nacl.debug: main.c
	gcc ${CFLAGS} -g main.c libnacl.a -o nacl.debug

nacl: main.c
	gcc ${CFLAGS} -O3 -s -flto main.c libnacl.a -o nacl

libnacl:
	./build-nacl

