# bluetoothmgrd - BluetoothMgr daemon.

PROG=		bluetoothmgrd
MAN=

.PATH:		${.CURDIR}/src ${.CURDIR}/../common

SRCS=		main.c \
		paths.c \
		safefile.c \
		inflight.c \
		ipc.c \
		listen.c \
		state.c \
		proto.c \
		pairing.c \
		hcsecdctl.c \
		hosts.c \
		hcsecd.c \
		store.c \
		btaddr.c \
		sanitise.c \
		session.c \
		memcheck.c

LIBBTMGR_DIR=	${.CURDIR}/../lib/libbtmgr

CFLAGS+=	-I${.CURDIR}/src
CFLAGS+=	-I${.CURDIR}/../common
CFLAGS+=	-I${LIBBTMGR_DIR}
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# Extra flags from the command line go here, never in CFLAGS itself: a
# command-line CFLAGS assignment REPLACES the Makefile's, silently dropping
# every -I above. Use "make BTMGR_CFLAGS=-DBTMGR_MEMCHECK" instead.
CFLAGS+=	${BTMGR_CFLAGS}

# -lutil for pidfile(3), which both writes the pidfile rc.subr expects and
# locks out a second daemon.
LDADD=		${LIBBTMGR_DIR}/libbtmgr.a -L/usr/local/lib -ljansson \
		-lbluetooth -lutil
DPADD=		${LIBBTMGR_DIR}/libbtmgr.a

PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/sbin

# Without this the rc script is left behind and the service cannot be enabled.
# 555 rather than 444: rc.subr runs it.
FILESGROUPS=	FILES RCSCRIPT

# Not named bluetoothmgrd: that is PROG, and the two rules would collide.
RCSCRIPT=	bluetoothmgrd.rc
RCSCRIPTNAME=	bluetoothmgrd
RCSCRIPTDIR=	${PREFIX}/etc/rc.d
RCSCRIPTMODE=	555
CLEANFILES+=	${RCSCRIPT}

# command= has to name the real install path, so it follows BINDIR.
${RCSCRIPT}: ${.CURDIR}/rc.d/bluetoothmgrd.in
	sed -e 's|@SBINDIR@|${BINDIR}|g' ${.CURDIR}/rc.d/bluetoothmgrd.in > \
	    ${.TARGET}

# bsd.prog.mk installs into directories but does not create them.
all: ${RCSCRIPT}

beforeinstall: ${RCSCRIPT}
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} ${DESTDIR}${BINDIR}
	${INSTALL} -d -o ${SHAREOWN} -g ${SHAREGRP} ${DESTDIR}${RCSCRIPTDIR}

.include <bsd.prog.mk>
