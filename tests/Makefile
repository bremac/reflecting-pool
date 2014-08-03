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

.PATH: ${POOLD_SRC} ${REFLECTOR_SRC}
CFLAGS += -I${POOLD_SRC} -I${REFLECTOR_SRC}

.include <dpadd.mk>
.include <prog.mk>
