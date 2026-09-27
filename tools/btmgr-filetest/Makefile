# btmgr-filetest - verification for the A0 write discipline (SPEC.md A0).
#
# Needs no privilege, no hardware and no daemon: it drives common/safefile.c
# against a scratch directory. Build with
#
#	make -C tools/btmgr-filetest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# to have it assert that it leaked nothing, the same way the daemon does.

PROG=		btmgr-filetest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		safefile.c \
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
