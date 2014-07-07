PROG = tests
CFLAGS = -g -Wall -Wextra -fno-strict-aliasing

POOL_SRC = ${.CURDIR}/../pool
REFLECTOR_SRC = ${.CURDIR}/../reflector

SRCS = tests.c

# pool
SRCS +=

# reflector
SRCS += checksum.c hash.c localaddrs.c segments.c sessions.c

all: ${PROG}
	@./${PROG}

realinstall: ${PROG}

.PATH: ${POOL_SRC} ${REFLECTOR_SRC}
CFLAGS += -I${POOL_SRC} -I${REFLECTOR_SRC}

.include <prog.mk>
