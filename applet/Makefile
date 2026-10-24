# bluetoothmgr-applet - the MATE panel applet (PLAN.md M6).
#
# A module the panel dlopens, not a program. See src/main.c for why it is not
# out of process.

PREFIX?=	/usr/local

SHLIB_NAME=	libbluetoothmgr-applet.so
SHLIBDIR=	${PREFIX}/lib/mate-panel
MAN=

.PATH:		${.CURDIR}/src ${.CURDIR}/../common

SRCS=		main.c \
		ipc_client.c \
		linebuf.c \
		proto.c \
		sanitise.c \
		btaddr.c \
		memcheck.c

APPLET_CFLAGS!=	pkg-config --cflags libmatepanelapplet-4.0
APPLET_LIBS!=	pkg-config --libs libmatepanelapplet-4.0

CFLAGS+=	${APPLET_CFLAGS}
CFLAGS+=	-I${.CURDIR}/../common
CFLAGS+=	-I${.CURDIR}/../lib/libbtmgr
# proto.c includes daemon/src/state.h. See PLAN.md: common should not depend
# on daemon, and this -I is what that costs every consumer.
CFLAGS+=	-I${.CURDIR}/../daemon/src
CFLAGS+=	-I/usr/local/include
CFLAGS+=	-Wall -Wextra

# See daemon/Makefile: a command-line CFLAGS assignment would replace the
# whole variable and silently drop the pkg-config flags above.
CFLAGS+=	${BTMGR_CFLAGS}

LDADD+=		${APPLET_LIBS} -L/usr/local/lib -ljansson -lbluetooth

# The panel finds an applet by this file, not by the module, so installing the
# module alone leaves nothing in "Add to Panel".
FILESGROUPS=	FILES APPLETDEF

APPLETDEF=	data/org.ghostbsd.BluetoothMgrApplet.mate-panel-applet
APPLETDEFDIR=	${PREFIX}/share/mate-panel/applets

# bsd.lib.mk installs into directories but does not create them. Ownership is
# passed through so a staged install as an ordinary user works too.
beforeinstall:
	${INSTALL} -d -o ${LIBOWN} -g ${LIBGRP} ${DESTDIR}${SHLIBDIR}
	${INSTALL} -d -o ${SHAREOWN} -g ${SHAREGRP} ${DESTDIR}${APPLETDEFDIR}

.include <bsd.lib.mk>