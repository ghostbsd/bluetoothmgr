# btmgr-sesstest - verification for common/session.c (SPEC.md A5.3, A9).
#
# Needs no privilege, no hardware and no daemon.

PROG=		btmgr-sesstest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		session.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>
