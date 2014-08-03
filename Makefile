SUBDIR = libutil reflector tests

LIBUTIL = ${.CURDIR}/libutil/libutil.a
POOLD_SRC = ${.CURDIR}/poold
REFLECTOR_SRC = ${.CURDIR}/reflector

.export LIBUTIL
.export POOLD_SRC REFLECTOR_SRC

.include <subdir.mk>
