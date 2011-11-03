.PHONY: all

CFLAGS = -ansi -O2 -fPIC -Wall -Wno-deprecated-declarations -Wno-unused-function -I. -I../dmem -I/opt/openssl/include -L/opt/openssl/lib

all:
	gcc $(CFLAGS) -c ../dmem/src/vector.c ../dmem/src/hash.c ../dmem/src/zlib.c ../dmem/src/char.c
	gcc $(CFLAGS) -I. -I../mt/include -c *.c
	gcc $(CFLAGS) -lcrypto -lssl -lz -shared *.o -o libspdy.so
	gcc $(CFLAGS) -lcrypto -lssl libspdy.so client.c -o client
