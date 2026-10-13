# btmgr-ctltest - verification for common/hcsecdctl.c.
#
# Needs no root, no hardware and no running hcsecd: the module's pidfile and
# process name are overridable, so the test points it at its own pid. Build
# with
#
#	make -C tools/btmgr-ctltest BTMGR_CFLAGS=-DBTMGR_MEMCHECK
#
# to have it assert that it leaked nothing.

PROG=		btmgr-ctltest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		hcsecdctl.c \
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
