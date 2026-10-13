# btmgr-clienttest - verification for common/ipc_client.c.
#
# Stands up its own AF_UNIX listening socket, so no root and no daemon. Build
# with
#
#	make -C tools/btmgr-clienttest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# to have it assert that it leaked nothing.

PROG=		btmgr-clienttest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		ipc_client.c \
		proto.c \
		linebuf.c \
		memcheck.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-I${.CURDIR}/../../lib/libbtmgr
CFLAGS+=	-I${.CURDIR}/../../daemon/src
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# A test harness, not something to install.
LIBBTMGR_DIR=	${.CURDIR}/../../lib/libbtmgr
LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -L/usr/local/lib -ljansson -lbluetooth
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>
