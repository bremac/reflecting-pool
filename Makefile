.PHONY: clean runtests
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

all: reflector tests

clean:
	rm -f reflector runtests *.o

reflector: hash.o localaddrs.o reflector.o segments.o sessions.o

tests: hash.o localaddrs.o segments.o sessions.o tests.o

test: tests
	./tests
