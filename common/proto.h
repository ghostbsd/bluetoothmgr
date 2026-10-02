/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * proto.h - the IPC wire format. SPEC.md Part B, protocol version 0.
 *
 * One JSON object per line, newline terminated. Shared by the daemon and
 * every client, so that the encoder and the decoder can never disagree.
 *
 * Ownership: every proto_*_json() function returns a malloc'd, NUL terminated
 * string that the caller must free(). They return NULL on allocation failure.
 */

#ifndef BTMGR_PROTO_H_
#define	BTMGR_PROTO_H_

#include <stddef.h>

#include "state.h"

/* SPEC.md B2. Bumped on any breaking change. */
#define	BTMGR_PROTO_VERSION	0

/* SPEC.md B1.3. A longer line closes the connection unparsed. */
#define	BTMGR_LINE_MAX		((size_t)64 * 1024)

#define	BTMGR_CMD_NAME_MAX	32

/* A parsed command. SPEC.md B3 and B4. */
struct proto_cmd {
	int		id;
	char		name[BTMGR_CMD_NAME_MAX];

	/* Optional fields. has_* says whether the client supplied them. */
	int		has_addr;
	bdaddr_t	addr;
	int		has_timeout;
	int		timeout;
	int		has_on;
	int		on;
};

/*
 * Parse one line into a command.
 *
 * Returns 0 on success. On failure returns -1 and writes a machine readable
 * error code (SPEC.md B6) into code, which must be at least 32 bytes. The id
 * is still filled in when it could be recovered, so the caller can address the
 * error reply to the right request.
 */
int	proto_parse_cmd(const char *line, size_t len, struct proto_cmd *out,
	    char *code, size_t codelen);

/* Daemon to client. Each returns a malloc'd line including its '\n'. */
char	*proto_hello(void);
char	*proto_state_event(const struct state *st);
char	*proto_ok(int id);
char	*proto_error(int id, const char *code, const char *detail);

#endif /* !BTMGR_PROTO_H_ */