PROG = tests
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

SRCS = tests.c

# poold
SRCS +=

# reflector
SRCS += checksum.c localaddrs.c sessions.c
DPLIBS = ${LIBUTIL}

all: ${PROG}
	@./${PROG}

realinstall: ${PROG}

.PATH: ${POOLD_SRC} ${REFLECTD_SRC}
CFLAGS += -I${POOLD_SRC} -I${REFLECTD_SRC}

.include <dpadd.mk>
.include <prog.mk>
