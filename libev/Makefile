LIB = ev
CFLAGS = -O2 -fno-strict-aliasing
CFLAGS += -DEV_STANDALONE=1
CFLAGS += -w  # libev's coding style tends to generate warnings from gcc

MKPIC = no
MKPROFILE = no

SRCS = ev.c  # ev.c #includes all of the other .c files

.include <lib.mk>
