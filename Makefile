SUBDIR = libev reflector tests

LIBEV = ${.CURDIR}/libev/libev.a

POOL_SRC = ${.CURDIR}/pool
REFLECTOR_SRC = ${.CURDIR}/reflector

.export LIBEV
.export POOL_SRC REFLECTOR_SRC

.include <subdir.mk>
