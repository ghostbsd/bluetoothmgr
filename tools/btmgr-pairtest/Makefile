# btmgr-pairtest - verification for common/pairing.c (SPEC.md A6, A8).
#
# Writes real files, but under a rooted btmgr_paths in a mkdtemp directory, so
# never /etc. For leak checking:
#
#	make -C tools/btmgr-pairtest BTMGR_CFLAGS=-DBTMGR_MEMCHECK

PROG=		btmgr-pairtest
MAN=

.PATH:		${.CURDIR}/../../common

SRCS=		main.c \
		pairing.c \
		paths.c \
		safefile.c \
		hosts.c \
		hcsecd.c \
		store.c \
		btaddr.c \
		sanitise.c \
		memcheck.c

CFLAGS+=	-I${.CURDIR}/../../common
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop every -I above.
CFLAGS+=	${BTMGR_CFLAGS}

# store.c uses jansson.
LDADD=		-L/usr/local/lib -ljansson

# A test harness, not something to install.
BINDIR?=	/usr/local/bin
NO_INSTALL=

.include <bsd.prog.mk>