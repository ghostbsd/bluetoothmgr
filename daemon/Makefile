# bluetoothmgrd - BluetoothMgr daemon.

PROG=		bluetoothmgrd
MAN=

.PATH:		${.CURDIR}/src ${.CURDIR}/../common

SRCS=		main.c \
		ipc.c \
		listen.c \
		state.c \
		proto.c

LIBBTMGR_DIR=	${.CURDIR}/../lib/libbtmgr

CFLAGS+=	-I${.CURDIR}/src
CFLAGS+=	-I${.CURDIR}/../common
CFLAGS+=	-I${LIBBTMGR_DIR}
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -L/usr/local/lib -ljansson -lbluetooth
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

BINDIR?=	/usr/local/sbin

.include <bsd.prog.mk>