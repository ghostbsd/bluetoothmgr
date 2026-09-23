# Datapoint gatherers used while planning BluetoothMgr.
# Run as an ordinary user: all three are expected to work without root,
# except the one SET_DEBUG ioctl in probe2, which must fail with EPERM.
#
#	make && ./probe1-enum && ./probe2-privilege && ./probe3-adapter

PROGS=	probe1-enum probe2-privilege probe3-adapter
CFLAGS+=	-Wall -Wextra -O0 -g
LDLIBS=	-lbluetooth

all: ${PROGS}

.c:
	${CC} ${CFLAGS} -o ${.TARGET} ${.IMPSRC} ${LDLIBS}

clean:
	rm -f ${PROGS}

.PHONY: all clean
