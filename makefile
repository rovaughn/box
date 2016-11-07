
sodium_ver := 1.0.11

all: testlog

testlog: box.debug test
	./test 2>&1 | tee testlog

libsodium-${sodium_ver}.tar.gz:
	wget 'https://download.libsodium.org/libsodium/releases/libsodium-${sodium_ver}.tar.gz'

libsodium.musl: libsodium-${sodium_ver}.tar.gz
	rm -rf libsodium-${sodium_ver}
	tar xaf libsodium-${sodium_ver}.tar.gz
	cd libsodium-${sodium_ver} && CC=musl-gcc ./configure --prefix=$(shell readlink -f $@)
	cd libsodium-${sodium_ver} && make
	cd libsodium-${sodium_ver} && make install
	rm -rf libsodium-${sodium_ver}

libsodium: libsodium-${sodium_ver}.tar.gz
	rm -rf libsodium-${sodium_ver}
	tar xaf libsodium-${sodium_ver}.tar.gz
	cd libsodium-${sodium_ver} && ./configure --prefix=$(shell readlink -f $@)
	cd libsodium-${sodium_ver} && make
	cd libsodium-${sodium_ver} && make install
	rm -rf libsodium-${sodium_ver}

sqlite-autoconf-3150100.tar.gz:
	wget 'https://www.sqlite.org/2016/sqlite-autoconf-3150100.tar.gz'

sqlite-autoconf-3150100: sqlite-autoconf-3150100.tar.gz
	tar xaf $^

sqlite3.c: sqlite-autoconf-3150100
	ln -fs $^/sqlite3.c .

sqlite3.h: sqlite-autoconf-3150100
	ln -fs $^/sqlite3.h .

box.debug: main.c libsodium sqlite3.c sqlite3.h
	gcc -Wall -Werror -g main.c readpass.c insecure_memzero.c warnp.c sqlite3.c \
		-lsodium -lpthread -ldl -Ilibsodium/include -Llibsodium/lib -o $@

box: main.c libsodium.musl sqlite3.c sqlite3.h
	musl-gcc -Wall -Werror -I/usr/local/include -O3 -static -flto \
		     main.c readpass.c insecure_memzero.c warnp.c sqlite3.c \
		     -Ilibsodium.musl/include -lsodium -Llibsodium.musl/lib -o $@
	strip -s box
	ls -lah box

clean:
	rm -rf libsodium-${sodium_ver}.tar.gz libsodium.musl libsodium \
		   sqlite-autoconf-3150100.tar.gz sqlite3 sqlite3.h box box.debug \
		   testlog

