# btmgr-keystest - verification for common/keys.c (SPEC.md A3).
#
# Needs no privilege and touches no file. For leak checking:
#
#	make -C tools/btmgr-keystest BTMGR_CFLAGS=-DBTMGR_MEMCHECK

PROG=		btmgr-keystest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		btaddr.c \
		keys.c \
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
