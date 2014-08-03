BINDIR = /usr/sbin
PROG = reflector
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = bpf.c checksum.c localaddrs.c sessions.c reflector.c
DPLIBS = ${LIBUTIL}

.include <dpadd.mk>
.include <prog.mk>
