# btmgr-prototest - verification for common/proto.c, SPEC.md Part B.
#
# proto_parse_cmd() is the daemon's only reader of untrusted client input.
# Needs no root, no hardware and no daemon. Build with
#
#	make -C tools/btmgr-prototest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# to have it assert that it leaked nothing.

PROG=		btmgr-prototest
MAN=

.PATH:		${.CURDIR}/../../common ${.CURDIR}/../../daemon/src

SRCS=		main.c \
		proto.c \
		state.c \
		sanitise.c \
		btaddr.c \
		memcheck.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-I${.CURDIR}/../../daemon/src
CFLAGS+=	-I${.CURDIR}/../../lib/libbtmgr
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# proto.c uses jansson; state.c and bt_aton need libbluetooth.
LIBBTMGR_DIR=	${.CURDIR}/../../lib/libbtmgr
LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -L/usr/local/lib -ljansson -lbluetooth
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>
