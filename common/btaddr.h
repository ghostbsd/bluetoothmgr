/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * btaddr.h - BD_ADDR text, in the two dialects the base system actually uses.
 *
 * These are not the same grammar and the difference is not cosmetic:
 *
 *   lenient  bt_aton(), one or two hex digits per field. Used by
 *            /etc/bluetooth/hosts and by hcsecd's keys file, both of which go
 *            through bt_aton(). 1:2:3:4:5:6 is valid.
 *   strict   hcsecd.conf's lexer, exactly two hex digits per field
 *            ({hexbyte} is {hexdigit}{hexdigit}). 1:2:3:4:5:6 is a parse error
 *            that stops hcsecd starting.
 *
 * They live together so that the three config parsers cannot quietly disagree
 * about what an address is, which is how a record ends up written in a form the
 * reader will not accept.
 *
 * Byte order throughout is libbluetooth's: addr[0] is the octet printed last.
 */

#ifndef BTMGR_BTADDR_H_
#define	BTMGR_BTADDR_H_

#include <stddef.h>
#include <stdint.h>

#define	BTMGR_ADDR_LEN		6
#define	BTMGR_ADDR_STRLEN	17	/* "00:11:22:33:44:55" */
#define	BTMGR_ADDR_BUFSZ	(BTMGR_ADDR_STRLEN + 1)

/* Value of one hex digit, or -1. Here so every parser agrees on it. */
int	btmgr_hex_digit(char c);

/* bt_aton() semantics. Returns 0, or -1 if s[0..len) is not an address. */
int	btmgr_addr_parse(const char *s, size_t len, uint8_t *out);

/* hcsecd.conf's lexer: six fields of exactly two hex digits. */
int	btmgr_addr_parse_strict(const char *s, size_t len, uint8_t *out);

/*
 * Format as bt_ntoa() does, lower case, two digits per field. out needs
 * BTMGR_ADDR_BUFSZ. Always writes the full 17 characters plus NUL.
 */
void	btmgr_addr_format(const uint8_t *addr, char *out, size_t outlen);

#endif /* !BTMGR_BTADDR_H_ */
