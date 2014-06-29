.PHONY: clean runtests
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

all: reflector test

clean:
	rm -f reflector runtests *.o

reflector: checksum.o hash.o localaddrs.o reflector.o segments.o sessions.o

tests: checksum.o hash.o localaddrs.o segments.o sessions.o tests.o

test: tests
	./tests
