.PHONY: clean test
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing
SRCS = checksum.c hash.c localaddrs.c segments.c sessions.c
OBJS = $(SRCS:.c=.o)

all: reflector test

clean:
	rm -f reflector tests *.o

reflector: $(OBJS) reflector.o

tests: $(OBJS) tests.o

test: tests
	./tests
