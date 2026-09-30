/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * sanitise.c - device-supplied strings made safe. SPEC.md A7, A2.2 to A2.5.
 *
 * Bytes are classified by explicit comparison, not <ctype.h>: the charset is a
 * file grammar, not a locale question, and ctype is undefined for the negative
 * int a plain char gives for a UTF-8 byte.
 */

#include <sys/cdefs.h>
#include <sys/types.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "btaddr.h"
#include "sanitise.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

static int	 alias_byte_ok(unsigned char c);
static int	 is_separator(unsigned char c);
static int	 is_alnum(unsigned char c);
static size_t	 trim_separators(char *s, size_t len);

static int
is_alnum(unsigned char c)
{

	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
	    (c >= '0' && c <= '9'));
}

static int
is_separator(unsigned char c)
{

	return (c == '.' || c == '_' || c == '-');
}

/* The A2.2 charset. */
static int
alias_byte_ok(unsigned char c)
{

	return (is_alnum(c) || is_separator(c));
}

/* Drop trailing separators in place, returning the new length. */
static size_t
trim_separators(char *s, size_t len)
{

	while (len > 0 && is_separator((unsigned char)s[len - 1]))
		len--;
	s[len] = '\0';

	return (len);
}

/* A7.1. */
int
btmgr_sanitise_quoted(const char *in, char *out, size_t outlen)
{
	size_t	 i, len;

	if (in == NULL || out == NULL) {
		errno = EINVAL;
		return (-1);
	}

	len = strlen(in);
	if (outlen < len + 1) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)in[i];

		if (c == '"' || c == '\\' || c < 0x20 || c == 0x7f)
			out[i] = '_';
		else
			out[i] = (char)c;
	}
	out[len] = '\0';

	return (0);
}

/*
 * A7.2, A7.4, A2.3. One pass straight into out, stopping at the budget: there
 * is no reason to transliterate 232 bytes of a 248 byte name to discard them.
 */
int
btmgr_alias_from_name(const char *name, const uint8_t *addr,
    char *out, size_t outlen)
{
	char	 tmp[BTMGR_ALIAS_BUFSZ];
	size_t	 len, i;
	int	 seen_alnum;

	if (out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (outlen < BTMGR_ALIAS_BUFSZ) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	/* Built aside, copied out only on success, so a failure leaves out. */
	len = 0;
	seen_alnum = 0;

	for (i = 0; name != NULL && name[i] != '\0' &&
	    len < BTMGR_ALIAS_MAX; i++) {
		unsigned char c = (unsigned char)name[i];
		char mapped;

		mapped = alias_byte_ok(c) ? (char)c : '_';

		if (is_separator((unsigned char)mapped)) {
			/* No leading separator, no runs. */
			if (len == 0 ||
			    is_separator((unsigned char)tmp[len - 1]))
				continue;
		} else
			seen_alnum = 1;

		tmp[len++] = mapped;
	}
	tmp[len] = '\0';

	len = trim_separators(tmp, len);

	/*
	 * A7.4. Tested as "no alnum survived" rather than "empty": a name of
	 * only emoji gives a row of underscores, which is no more use.
	 * bt_ntoa() prints b[5] first, so the printed tail is b[2], b[1], b[0].
	 */
	if (len == 0 || !seen_alnum) {
		if (addr == NULL) {
			errno = EINVAL;
			return (-1);
		}
		snprintf(tmp, sizeof(tmp), "bt-%02x%02x%02x",
		    (unsigned int)addr[2], (unsigned int)addr[1],
		    (unsigned int)addr[0]);
	}

	strlcpy(out, tmp, outlen);

	return (0);
}

/* A2.4. */
int
btmgr_alias_with_suffix(const char *stem, unsigned int n,
    char *out, size_t outlen)
{
	char	 tmp[BTMGR_ALIAS_BUFSZ];
	char	 suffix[16];
	size_t	 stemlen, sufflen, keep;

	if (stem == NULL || out == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (outlen < BTMGR_ALIAS_BUFSZ) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	snprintf(suffix, sizeof(suffix), "%u", n);
	sufflen = strlen(suffix);

	/*
	 * Keep room for a stem: an alias that is only digits identifies
	 * nothing. Unreachable for an unsigned int, whose widest decimal is 10,
	 * but the budget is a #define and this is the guard if it shrinks.
	 */
	if (sufflen + 1 > BTMGR_ALIAS_MAX) {
		errno = EINVAL;
		return (-1);
	}

	keep = BTMGR_ALIAS_MAX - sufflen;
	stemlen = strlen(stem);
	if (stemlen > keep)
		stemlen = keep;

	memcpy(tmp, stem, stemlen);
	stemlen = trim_separators(tmp, stemlen);
	if (stemlen == 0) {
		errno = EINVAL;
		return (-1);
	}

	memcpy(tmp + stemlen, suffix, sufflen + 1);
	strlcpy(out, tmp, outlen);

	return (0);
}

/* A2.5. Mirrors bt_aton() rather than calling it, to keep bluetooth.h out. */
int
btmgr_alias_is_addrlike(const char *s)
{
	int	 field, digits;

	if (s == NULL || *s == '\0')
		return (0);

	for (field = 0; field < 6; field++) {
		for (digits = 0; btmgr_hex_digit(*s) >= 0; digits++)
			s++;

		if (digits < 1 || digits > 2)
			return (0);

		if (field < 5) {
			if (*s != ':')
				return (0);
			s++;
		}
	}

	return (*s == '\0');
}

int
btmgr_alias_is_valid(const char *s)
{
	size_t	 i;
	int	 seen_alnum;

	if (s == NULL || *s == '\0')
		return (0);

	seen_alnum = 0;
	for (i = 0; s[i] != '\0'; i++) {
		unsigned char c = (unsigned char)s[i];

		if (!alias_byte_ok(c))
			return (0);
		if (is_alnum(c))
			seen_alnum = 1;
	}

	if (i > BTMGR_ALIAS_MAX || !seen_alnum)
		return (0);

	return (!btmgr_alias_is_addrlike(s));
}