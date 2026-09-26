# BluetoothMgr
#
#	make		build everything
#	make clean	remove build products
#
# lib must come before tools, since btmgr-probe links libbtmgr.a.

SUBDIR=		lib \
		daemon \
		tools

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>