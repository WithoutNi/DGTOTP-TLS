CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99
LDLIBS=-lssl -lcrypto

all:client verifier server
client:client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
verifier:verifier.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
server:server.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f client verifier server

.PHONY:all clean