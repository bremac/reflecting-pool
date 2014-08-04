SUBDIR = libutil reflectd tests

LIBUTIL = ${.CURDIR}/libutil/libutil.a
POOLD_SRC = ${.CURDIR}/poold
REFLECTD_SRC = ${.CURDIR}/reflectd

.export LIBUTIL
.export POOLD_SRC REFLECTD_SRC

.include <subdir.mk>
