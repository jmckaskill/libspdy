.PHONY: all

CFLAGS = -ansi -g -fPIC -Wall -Wno-deprecated-declarations -Wno-unused-function -I. -I../dmem -I/opt/openssl/include -L/opt/openssl/lib -D_GNU_SOURCE

all:
	gcc $(CFLAGS) -c ../dmem/src/vector.c ../dmem/src/hash.c ../dmem/src/zlib.c ../dmem/src/char.c
	gcc $(CFLAGS) -I. -I../mt/include -c *.c
	gcc $(CFLAGS) -luuid -lcrypto -lssl -lz -Xlinker -rpath /opt/openssl/lib -shared *.o -o libspdy.so
	gcc $(CFLAGS) -lcrypto -lssl -Xlinker -rpath /opt/openssl/lib libspdy.so client.c -o client
