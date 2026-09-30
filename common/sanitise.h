/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * sanitise.h - device-supplied strings made safe. SPEC.md A7, A2.2 to A2.5.
 *
 * Remote names reach two files with no escape mechanism: a quote or newline
 * corrupts the hcsecd parse (A1.1.4), a space splits a hosts record. Done here
 * once so no generator can forget it.
 *
 * A7.3 has no function here: it is satisfied by never calling system(3).
 */

#ifndef BTMGR_SANITISE_H_
#define	BTMGR_SANITISE_H_

#include <stddef.h>
#include <stdint.h>

/* A2.3. See SPEC.md: 16 is the conservative reading of the virtual_oss limit. */
#define	BTMGR_ALIAS_MAX		16
#define	BTMGR_ALIAS_BUFSZ	(BTMGR_ALIAS_MAX + 1)

/*
 * A7.1. Replace '"', '\', C0 controls and DEL with '_'; pass 0x80 and above
 * through. Output is never longer than the input, so outlen of strlen(in) + 1
 * suffices. Returns 0, or -1 with EINVAL or ENAMETOOLONG.
 */
int	btmgr_sanitise_quoted(const char *in, char *out, size_t outlen);

/*
 * A7.2, A7.4, A2.3. Transliterate name to [A-Za-z0-9._-], collapse runs of
 * '_', trim leading and trailing separators, truncate to BTMGR_ALIAS_MAX. If
 * no letter or digit survives, fall back to "bt-" plus the last three octets.
 *
 * addr is a bdaddr_t's six bytes, b[0] first (pass dev->bdaddr.b). Needed for
 * the fallback; NULL there gives EINVAL. out needs BTMGR_ALIAS_BUFSZ and is
 * left untouched on failure.
 */
int	btmgr_alias_from_name(const char *name, const uint8_t *addr,
	    char *out, size_t outlen);

/*
 * A2.4. Build the n'th variant of a taken alias: bare digit suffix, stem
 * truncated to fit and its trailing separators dropped. The caller owns the
 * search, trying 2, 3, 4 until one is free. out needs BTMGR_ALIAS_BUFSZ and is
 * left untouched on failure.
 */
int	btmgr_alias_with_suffix(const char *stem, unsigned int n,
	    char *out, size_t outlen);

/*
 * A2.5. Would bt_aton() read this as an address, making it unreachable through
 * hosts? Six colon separated fields of one or two hex digits, so 1:2:3:4:5:6
 * counts. A7.2 already makes this unreachable, since ':' cannot survive it.
 */
int	btmgr_alias_is_addrlike(const char *s);

/* Non-empty, <= BTMGR_ALIAS_MAX, in charset, has an alnum, not address-like. */
int	btmgr_alias_is_valid(const char *s);

#endif /* !BTMGR_SANITISE_H_ */
