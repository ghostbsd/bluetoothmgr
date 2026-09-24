# btmgr-probe - read-only CLI over libbtmgr.

PROG=		btmgr-probe
SRCS=		main.c
MAN=

LIBBTMGR_DIR=	${.CURDIR}/../../lib/libbtmgr

CFLAGS+=	-I${LIBBTMGR_DIR}
CFLAGS+=	-Wall -Wextra

LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -lbluetooth
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

.include <bsd.prog.mk>