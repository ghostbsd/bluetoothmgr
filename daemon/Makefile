# bluetoothmgrd - BluetoothMgr daemon.

PROG=		bluetoothmgrd
MAN=

.PATH:		${.CURDIR}/src ${.CURDIR}/../common

SRCS=		main.c \
		paths.c \
		safefile.c \
		inflight.c \
		ipc.c \
		listen.c \
		state.c \
		proto.c \
		memcheck.c

LIBBTMGR_DIR=	${.CURDIR}/../lib/libbtmgr

CFLAGS+=	-I${.CURDIR}/src
CFLAGS+=	-I${.CURDIR}/../common
CFLAGS+=	-I${LIBBTMGR_DIR}
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# Extra flags from the command line go here, never in CFLAGS itself: a
# command-line CFLAGS assignment REPLACES the Makefile's, silently dropping
# every -I above. Use "make BTMGR_CFLAGS=-DBTMGR_MEMCHECK" instead.
CFLAGS+=	${BTMGR_CFLAGS}

LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -L/usr/local/lib -ljansson -lbluetooth
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

BINDIR?=	/usr/local/sbin

.include <bsd.prog.mk>