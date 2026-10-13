# btmgr-linetest - verification for common/linebuf.c.
#
# Drives it over a socketpair, so no root, no daemon, no hardware. Build with
#
#	make -C tools/btmgr-linetest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# to have it assert that it leaked nothing.

PROG=		btmgr-linetest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		linebuf.c \
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
