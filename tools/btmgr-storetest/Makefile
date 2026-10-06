# btmgr-storetest - verification for common/store.c (SPEC.md A4).
#
# Needs no privilege and touches no file. For leak checking:
#
#	make -C tools/btmgr-storetest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# Note that jansson allocates through its own allocator, so memcheck sees only
# this project's allocations. That is the balance we care about.

PROG=		btmgr-storetest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		btaddr.c \
		store.c \
		memcheck.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

LDADD=		-L/usr/local/lib -ljansson

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>
