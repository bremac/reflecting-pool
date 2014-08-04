BINDIR = /usr/sbin
PROG = reflectd
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = bpf.c checksum.c localaddrs.c sessions.c reflectd.c
DPLIBS = ${LIBUTIL}

.include <dpadd.mk>
.include <prog.mk>
