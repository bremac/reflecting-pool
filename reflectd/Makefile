BINDIR = /usr/sbin
PROG = reflectd
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = addrset.c bpf.c checksum.c sessions.c reflectd.c
DPLIBS = ${LIBUTIL}

.include <dpadd.mk>
.include <prog.mk>
