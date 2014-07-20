SUBDIR = libev reflector tests

POOL_SRC = ${.CURDIR}/pool
REFLECTOR_SRC = ${.CURDIR}/reflector

.export POOL_SRC REFLECTOR_SRC

.include <subdir.mk>
