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

#include "btmgr.h"

/*
 * Only proto_state_event() needs it, and only by pointer, so a frontend
 * including this does not drag in daemon/src/state.h.
 */
struct state;

/* SPEC.md B2. Bumped on any breaking change. */
#define	BTMGR_PROTO_VERSION	0

/* SPEC.md B1.3. A longer line closes the connection unparsed. */
#define	BTMGR_LINE_MAX		((size_t)64 * 1024)

#define	BTMGR_CMD_NAME_MAX	32

/*
 * A legacy Bluetooth PIN is at most 16 bytes: NG_HCI_PIN_SIZE, the width of
 * the pin field in ng_hci_pin_code_rep_cp. A longer one could never be sent,
 * so it is refused here rather than truncated into a wrong secret.
 */
#define	BTMGR_PIN_MAX		16

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
	int		has_pin;
	char		pin[BTMGR_PIN_MAX + 1];

	/* From the client's scan. Without it A2 aliases everything bt-xxxxxx. */
	int		has_device_name;
	char		device_name[BTMGR_NAME_SIZE];
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

#define	BTMGR_ERROR_CODE_MAX	32
#define	BTMGR_DETAIL_MAX	256
#define	BTMGR_EVENT_NAME_MAX	32

/* SPEC.md B3.3: a message carrying id is a reply, one carrying event is not. */
enum proto_msg_kind {
	PROTO_MSG_REPLY = 1,
	PROTO_MSG_EVENT
};

/* The scalars of a state event. B5's arrays wait for a UI that shows them. */
struct proto_adapter_state {
	int	adapter_present;
	int	powered;
	int	discoverable;
	int	scanning;
	int	config_readable;
	int	connection_count;
};

struct proto_msg {
	enum proto_msg_kind	kind;

	/* PROTO_MSG_REPLY */
	int			request_id;
	int			succeeded;
	char			error_code[BTMGR_ERROR_CODE_MAX];
	char			error_detail[BTMGR_DETAIL_MAX];

	/* PROTO_MSG_EVENT */
	char			event_name[BTMGR_EVENT_NAME_MAX];

	/* Set for the hello event, which B2.1 makes the client check. */
	int			has_proto_version;
	int			proto_version;

	/* Set for the state event only. */
	int			has_state;
	struct proto_adapter_state state;
};

/*
 * Decode one line from the daemon. Returns 0, or -1 when the line is not a
 * valid message. An event this build does not know still decodes, with
 * event_name set and nothing else, so new events in B7 do not break old
 * clients.
 */
int	proto_parse_msg(const char *line, size_t len, struct proto_msg *out);

/*
 * Client to daemon: the inverse of proto_parse_cmd, so a round trip through
 * both is what keeps the two from disagreeing. Only the fields proto_cmd
 * carries can be emitted, so scan, set_alias and set_trusted wait until their
 * fields exist. Returns NULL on bad input or allocation failure.
 */
char	*proto_encode_cmd(const struct proto_cmd *cmd);

/* Daemon to client. Each returns a malloc'd line including its '\n'. */
char	*proto_hello(void);
char	*proto_state_event(const struct state *st);
char	*proto_ok(int id);
char	*proto_error(int id, const char *code, const char *detail);

#endif /* !BTMGR_PROTO_H_ */
