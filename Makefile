# BluetoothMgr
#
#	make		build everything
#	make clean	remove build products
#	make tidy	clang-tidy gate; fails on a blocking finding
#	make memcheck	build the daemon with allocation tracking
#
# lib must come before tools, since btmgr-probe links libbtmgr.a.

SUBDIR=		lib \
		daemon \
		tools

SUBDIR_PARALLEL=

ANALYZE_INCS=	-Ilib/libbtmgr -Icommon -Idaemon/src -I/usr/local/include
ANALYZE_SRCS!=	echo lib/libbtmgr/*.c common/*.c daemon/src/*.c \
		tools/btmgr-probe/*.c tools/btmgr-filetest/*.c \
		tools/btmgr-strtest/*.c tools/btmgr-hoststest/*.c \
		tools/btmgr-secdtest/*.c tools/btmgr-keystest/*.c \
		tools/btmgr-storetest/*.c tools/btmgr-pathtest/*.c \
		tools/btmgr-pairtest/*.c

TIDY?=		clang-tidy19

# Clang's static analyzer runs as part of "make tidy": clang-analyzer-* is in
# .clang-tidy's check list, with the same Annex K checker disabled.
#
# There is deliberately no hand-rolled analyze target here any more. It could
# not work: "analyze" is in bsd.subdir.mk's SUBDIR_TARGETS, so make recurses
# into every subdirectory where bsd.clang-analyze.mk runs its own version
# WITHOUT our -analyzer-disable-checker, printing pages of Annex K noise. A
# root-level loop then added "analyze: clean" after all of it, which is worse
# than no target at all. "make analyze" is still the stock per-directory
# behaviour: advisory, noisy, and it exits 0 whatever it finds.
#
# Measured limits of the analyzer, so nobody mistakes a clean run for proof: it
# does NOT catch "p = realloc(p, n)" losing the original block on failure, nor a
# struct freed without freeing its fields. Those are what common/memcheck.c is
# for.

# clang-tidy, configured by .clang-tidy, which sets WarningsAsErrors. Unlike
# analyze this does fail, so it is the gate. It also runs the analyzer's own
# checkers, so a clean tidy subsumes a clean analyze.
# "N warnings generated" is clang tallying what HeaderFilterRegex suppressed in
# system headers, not findings of ours, so only real diagnostics are shown. The
# exit status comes from clang-tidy, never from the filter.
tidy:
	@log=$$(mktemp); fail=0; \
	for f in ${ANALYZE_SRCS}; do \
		${TIDY} --quiet $$f -- ${ANALYZE_INCS} -std=gnu17 \
		    -Wall -Wextra >> $$log 2>&1 || fail=1; \
	done; \
	grep -E "warning:|error:|note:" $$log || true; \
	rm -f $$log; \
	if [ $$fail -ne 0 ]; then \
		echo "tidy: FAILED"; \
		exit 1; \
	fi; \
	echo "tidy: clean"

# Build the daemon with the allocation tracker and report leaks on exit.
memcheck:
	@${MAKE} -C daemon cleandir > /dev/null
	@${MAKE} -C daemon BTMGR_CFLAGS=-DBTMGR_MEMCHECK
	@echo "memcheck: built daemon/bluetoothmgrd with tracking enabled"

.PHONY: memcheck tidy

.include <bsd.subdir.mk>