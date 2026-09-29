# btmgr-strtest - verification for common/sanitise.c (SPEC.md A7, A2.2 to A2.5).
#
# Needs no privilege, no hardware and no daemon. For leak checking:
#
#	make -C tools/btmgr-strtest BTMGR_CFLAGS=-DBTMGR_MEMCHECK

PROG=		btmgr-strtest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		sanitise.c \
		memcheck.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>