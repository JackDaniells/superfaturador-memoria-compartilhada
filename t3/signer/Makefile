CC=gcc
CFLAGS=-I. -g -O0

signer: main.c sha256.c
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

all: signer

PHONY: clean

clean:
	rm -f *.o signer
