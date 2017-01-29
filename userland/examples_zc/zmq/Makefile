INCLUDE= $(shell pkg-config --cflags libzmq)
LIBS=$(shell pkg-config --libs libzmq)
CC=gcc -g

all: client server

client: client.c common.h Makefile
	$(CC) $(INCLUDE) client.c $(LIBS) -o client 

server: server.c common.h Makefile
	$(CC) $(INCLUDE) server.c $(LIBS) -o server 

clean:
	/bin/rm -f *~ client server
	/bin/rm -rf *.dSYM
