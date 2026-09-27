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

ANALYZE_INCS=	-Ilib/libbtmgr -Icommon -Idaemon/src -I/usr/local/include
ANALYZE_SRCS!=	echo lib/libbtmgr/*.c common/*.c daemon/src/*.c \
		tools/btmgr-probe/*.c tools/btmgr-filetest/*.c

# Clang's static analyzer. Catches intra-function leaks, double frees and
# use-after-free on a pointer it can follow from allocation to scope exit.
#
# Measured limits, so nobody mistakes a clean run for proof: it does NOT catch
# "p = realloc(p, n)" losing the original block on failure, nor a struct freed
# without freeing its fields. Those are what common/memcheck.c is for.
analyze:
	@for f in ${ANALYZE_SRCS}; do \
		${CC} --analyze -Xclang -analyzer-output=text \
		    -Xanalyzer -analyzer-disable-checker \
		    -Xanalyzer security.insecureAPI \
		    ${ANALYZE_INCS} $$f || exit 1; \
	done
	@echo "analyze: clean"

# Build the daemon with the allocation tracker and report leaks on exit.
memcheck:
	@${MAKE} -C daemon cleandir > /dev/null
	@${MAKE} -C daemon BTMGR_CFLAGS=-DBTMGR_MEMCHECK
	@echo "memcheck: built daemon/bluetoothmgrd with tracking enabled"

.PHONY: analyze memcheck

.include <bsd.subdir.mk>