# btmgr-secdtest - verification for common/hcsecd.c (SPEC.md A1, A0.3, A0.4).
#
# Needs no privilege and touches no file. For leak checking:
#
#	make -C tools/btmgr-secdtest BTMGR_CFLAGS=-DBTMGR_MEMCHECK

PROG=		btmgr-secdtest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		btaddr.c \
		hcsecd.c \
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
