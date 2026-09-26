# libbtmgr - the HCI layer.
#
# INTERNALLIB means a static libbtmgr.a that gets linked into each consumer
# and is never installed. There is no shared object and no public ABI to
# maintain. See PLAN.md 4.1.

LIB=		btmgr
INTERNALLIB=

SRCS=		adapter.c \
		class.c \
		conn.c \
		ops.c \
		scan.c

CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-Wall -Wextra

# bsd.prog.mk links programs as PIE by default (MK_PIE=yes), and every object
# that goes into a PIE must be position independent. INTERNALLIB otherwise
# builds plain objects, so the link fails with "relocation R_X86_64_64 cannot
# be used against local symbol". Build the archive PIC rather than turning the
# hardening off on the consumer side.
CFLAGS+=	-fPIC

.include <bsd.lib.mk>