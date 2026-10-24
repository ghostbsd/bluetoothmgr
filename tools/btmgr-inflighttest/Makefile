# btmgr-inflighttest - verification for daemon/src/inflight.c.
#
# Needs no privilege, no hardware and no daemon. struct client is only ever a
# pointer here, so the table links without the IPC layer behind it.

PROG=		btmgr-inflighttest
MAN=

.PATH:		${.CURDIR}/../../daemon/src

SRCS=		main.c \
		inflight.c

CFLAGS+=	-I${.CURDIR}/../../daemon/src
CFLAGS+=	-I${.CURDIR}/../../lib/libbtmgr
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>
