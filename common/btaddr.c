/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btaddr.c - BD_ADDR text. See btaddr.h for why there are two dialects.
 *
 * Both fill out[5] down to out[0], so the first field read is the last byte
 * stored. That is bt_aton()'s order and bt_ntoa() prints it back the same way.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "btaddr.h"

int
btmgr_hex_digit(char ch)
{
	unsigned char	 c = (unsigned char)ch;

	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);

	return (-1);
}

/* Mirrors bt_aton() at lib/libbluetooth/bluetooth.c:289. */
int
btmgr_addr_parse(const char *s, size_t len, uint8_t *out)
{
	size_t	 i;
	int	 field, digits, v, b;

	if (s == NULL || out == NULL)
		return (-1);

	i = 0;
	for (field = 5; field >= 0; field--) {
		v = 0;
		for (digits = 0; i < len &&
		    (b = btmgr_hex_digit(s[i])) >= 0; digits++, i++) {
			if (digits == 2)
				return (-1);
			v = v * 16 + b;
		}
		if (digits == 0)
			return (-1);

		out[field] = (uint8_t)v;

		if (field > 0) {
			if (i >= len || s[i] != ':')
				return (-1);
			i++;
		}
	}

	return (i == len ? 0 : -1);
}

/* Mirrors hcsecd's lexer rule bdaddrstring in lexer.l. */
int
btmgr_addr_parse_strict(const char *s, size_t len, uint8_t *out)
{
	size_t	 i;
	int	 field, hi, lo;

	if (s == NULL || out == NULL || len != BTMGR_ADDR_STRLEN)
		return (-1);

	i = 0;
	for (field = 5; field >= 0; field--) {
		hi = btmgr_hex_digit(s[i]);
		lo = btmgr_hex_digit(s[i + 1]);
		if (hi < 0 || lo < 0)
			return (-1);
		out[field] = (uint8_t)(hi * 16 + lo);
		i += 2;

		if (field > 0) {
			if (s[i] != ':')
				return (-1);
			i++;
		}
	}

	return (0);
}

void
btmgr_addr_format(const uint8_t *addr, char *out, size_t outlen)
{

	(void)snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
	    (unsigned int)addr[5], (unsigned int)addr[4],
	    (unsigned int)addr[3], (unsigned int)addr[2],
	    (unsigned int)addr[1], (unsigned int)addr[0]);
}
