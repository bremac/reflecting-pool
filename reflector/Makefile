BINDIR = /usr/sbin
PROG = reflector
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = bpf.c checksum.c hash.c localaddrs.c sessions.c reflector.c
DPLIBS = ${LIBEV}

.include <dpadd.mk>
.include <prog.mk>
