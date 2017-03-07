
sodium_ver := 1.0.11
sqlite_ver := 3150100

.PHONY: clean

all: testlog

testlog: box.debug test
	./test 2>&1 | tee testlog

libsodium-${sodium_ver}.tar.gz:
	wget 'https://download.libsodium.org/libsodium/releases/libsodium-${sodium_ver}.tar.gz'

libsodium.musl: libsodium-${sodium_ver}.tar.gz
	rm -rf libsodium-${sodium_ver}
	tar -xf libsodium-${sodium_ver}.tar.gz
	cd libsodium-${sodium_ver} && CC=musl-gcc ./configure --prefix=$(shell pwd)/$@
	cd libsodium-${sodium_ver} && make
	cd libsodium-${sodium_ver} && make install
	rm -rf libsodium-${sodium_ver}

libsodium: libsodium-${sodium_ver}.tar.gz
	rm -rf libsodium-${sodium_ver}
	tar -xf libsodium-${sodium_ver}.tar.gz
	cd libsodium-${sodium_ver} && ./configure --prefix=$(shell pwd)/$@
	cd libsodium-${sodium_ver} && make
	cd libsodium-${sodium_ver} && make install
	rm -rf libsodium-${sodium_ver}

/usr/local/lib/libsodium.so: libsodium-${sodium_ver}.tar.gz
	rm -rf libsodium-${sodium_ver}
	tar -xf libsodium-${sodium_ver}.tar.gz
	cd libsodium-${sodium_ver} && ./configure
	cd libsodium-${sodium_ver} && make
	cd libsodium-${sodium_ver} && sudo make install
	rm -rf libsodium-${sodium_ver}
	touch .libsodium-global

sqlite-autoconf-${sqlite_ver}.tar.gz:
	wget 'https://www.sqlite.org/2016/sqlite-autoconf-${sqlite_ver}.tar.gz'

sqlite-autoconf-${sqlite_ver}: sqlite-autoconf-${sqlite_ver}.tar.gz
	tar -xf $^
	touch $@

sqlite3.c: sqlite-autoconf-${sqlite_ver}
	ln -fs $^/sqlite3.c .
	touch $@

sqlite3.h: sqlite-autoconf-${sqlite_ver}
	ln -fs $^/sqlite3.h .
	touch $@

box.debug: main.c libsodium sqlite3.c sqlite3.h
	gcc -Wall -Werror -g main.c readpass.c insecure_memzero.c warnp.c sqlite3.c \
		-lsodium -lpthread -ldl -Ilibsodium/include -Llibsodium/lib -o $@

box.musl: main.c libsodium.musl sqlite3.c sqlite3.h
	musl-gcc -Wall -Werror -I/usr/local/include -O2 -march=native -static \
		     -flto main.c readpass.c insecure_memzero.c warnp.c sqlite3.c \
		     -Ilibsodium.musl/include -lsodium -Llibsodium.musl/lib -o $@
	strip -s $@
	ln -sf $@ box

box.mac: /usr/local/lib/libsodium.so main.c sqlite3.c sqlite3.h
	gcc -Wall -Werror -O3 -flto \
		main.c readpass.c insecure_memzero.c warnp.c sqlite3.c -lsodium -lpthread \
		-ldl -o $@
	ln -sf $@ box

clean:
	rm -rf libsodium-*.tar.gz libsodium.musl libsodium \
		     sqlite-autoconf-*.tar.gz sqlite3 sqlite3.h box box.debug \
		     testlog
