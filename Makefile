.PHONY: all

CFLAGS = -Wall -Wno-deprecated-declarations -Wno-unused-function -I../dmem -I.

all:
	gcc $(CFLAGS) -c ../dmem/src/vector.c ../dmem/src/hash.c ../dmem/src/zlib.c ../dmem/src/char.c
	gcc $(CFLAGS) -I. -I../mt/include -c *.c
	gcc -lcrypto -lssl -lz -shared *.o -o libspdy.so
	gcc $(CFLAGS) -lcrypto -lssl libspdy.so client.c -o client
