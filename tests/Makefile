PROG = tests
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = tests.c

# poold
SRCS +=

# reflector
SRCS += addrset.c checksum.c sessions.c
DPLIBS = ${LIBUTIL}

all: ${PROG}
	@./${PROG}

realinstall: ${PROG}

.PATH: ${POOLD_SRC} ${REFLECTD_SRC}
CFLAGS += -I${POOLD_SRC} -I${REFLECTD_SRC}

.include <dpadd.mk>
.include <prog.mk>
