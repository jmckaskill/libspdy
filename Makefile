.PHONY: all

CFLAGS = -ansi -O2 -DNDEBUG -fPIC -Wall -Wno-deprecated-declarations -Wno-unused-function -I. -I../dmem -I/opt/openssl/include -L/opt/openssl/lib -D_GNU_SOURCE
LDFLAGS = $(CFLAGS) -Xlinker -rpath /opt/openssl/lib

all:
	rm -f *.o *.so client
	gcc $(CFLAGS) -c ../dmem/src/vector.c ../dmem/src/hash.c ../dmem/src/zlib.c ../dmem/src/char.c
	gcc $(CFLAGS) -I. -I../mt/include -c *.c
	gcc $(LDFLAGS) -lcrypto -lssl -lz *.o -o client
