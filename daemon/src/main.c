/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * bluetoothmgrd - BluetoothMgr daemon.
 *
 * One kqueue loop watching five kinds of thing at once: the listening socket,
 * each connected client's readability and writability, the passive HCI event
 * socket, signals, and a periodic reconcile timer.
 *
 * M2 performs no privileged operation at all. Per SPEC.md C1 the entire
 * polling path is on the kernel's unprivileged allowlist, so this can and
 * should be developed as an ordinary user:
 *
 *	./bluetoothmgrd -f -s /tmp/btmgr.sock
 *	nc -U /tmp/btmgr.sock
 *
 * The privileged half arrives in M3.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "btmgr.h"
#include "hcsecdctl.h"
#include "inflight.h"
#include "pairing.h"
#include "paths.h"
#include "ipc.h"
#include "listen.h"
#include "proto.h"
#include "state.h"

/*
 * Must come after the system headers: it redefines malloc and friends. The
 * pragma says so to clang-include-cleaner, which sees no direct use of this
 * header because the use is macro replacement of malloc(), not a symbol.
 */
#include "memcheck.h"	/* IWYU pragma: keep */

#define	DEFAULT_SOCKET	"/var/run/bluetoothmgr.sock"
#define	SOCKET_MODE	0660
#define	RECONCILE_MS	5000		/* SPEC.md C2.1: the safety net */

/*
 * Upper bound on a discoverability timeout, one hour. Bluetooth UIs offer
 * minutes, so this is generous; its job is to keep a client from reaching
 * integer overflow in the millisecond conversion.
 */
#define	BTMGR_DISCOVER_MAX_SEC	3600
#define	MAX_EVENTS	32

/*
 * How long a parked pairing waits for Link_Key_Notification. The user has to
 * read a PIN off a screen and type it on the device, so this is generous
 * compared with INFLIGHT_TIMEOUT_SEC, which only waits on the controller.
 */
#define	PAIRING_TIMEOUT_SEC	60

/*
 * udata tags. kqueue hands back whatever pointer we registered, so a distinct
 * address per source tells the handler what fired without a lookup table. For
 * clients we register the struct client * itself, which is the real payoff:
 * the event arrives with our own state already attached.
 */
static int	tag_listen_sock;	/* the IPC listening socket */
static int	tag_hci;		/* the passive HCI event socket */
static int	tag_timer;
static int	tag_discoverable;

/*
 * A6: one pairing at a time, because A6.2 forbids the reload a second one's
 * step 4 would need. client may die before the key arrives, so every use goes
 * through client_alive().
 */
struct parked_pairing {
	struct pair_state	 state;
	struct client		*client;
	int			 id;		/* the client's request id */
	uint16_t		 handle;	/* 0 until the link is up */
	time_t			 deadline;
	char			 name[BTMGR_NAME_SIZE];
};

struct daemon {
	int		 kq;
	int		 lfd;		/* IPC listening socket */
	int		 hci;		/* passive HCI event socket */
	const char	*sockpath;
	char		 node[HCI_DEVNAME_SIZE];
	struct client	*clients;
	struct state	 last;		/* last snapshot sent to clients */
	int		 have_last;
	int		 dirty;
	uid_t		 sockuid;	/* SPEC.md A5.3 */
	gid_t		 sockgid;
	struct btmgr_paths paths;	/* where the config files are */
	struct inflight_table	pending;
	struct hcsecd_ctl	hcsecd;		/* A8.1, the real pair_ops */
	struct parked_pairing	pairing;
	volatile int	 quit;
};

static void	usage(void);
static int	kq_add(int kq, uintptr_t ident, short filter, void *udata);
static int	kq_del(int kq, uintptr_t ident, short filter);
static void	broadcast(struct daemon *d, const char *line);
static int	client_alive(struct daemon *d, const struct client *c);
static void	drop_client(struct daemon *d, struct client *c);
static void	handle_line(struct daemon *d, struct client *c,
		    const char *line, size_t len);
static void	service_client(struct daemon *d, struct client *c);
static void	do_accept(struct daemon *d);
static void	reconcile(struct daemon *d);
static void	refresh_hci(struct daemon *d);
static void	reply(struct daemon *d, struct client *c, char *line);
static int	may_change(const struct daemon *d, const struct client *c);
static int	blocked_while_pairing(const char *cmd);
static struct pair_ops	pair_ops_for(struct daemon *d);
static void	finish_pairing(struct daemon *d, const bdaddr_t *addr);
static void	abandon_pairing(struct daemon *d, const char *code,
		    const char *why);
static void	do_pair(struct daemon *d, struct client *c,
		    const struct proto_cmd *cmd);
static void	on_completion(const struct listen_report *r, void *arg);
static void	on_expired(const struct inflight *f, void *arg);

static void
usage(void)
{
	(void)fprintf(stderr,
	    "usage: bluetoothmgrd [-f] [-n] [-r root] [-s socket]\n"
	    "\t-n\tdry run: report what would be written, write nothing\n"
	    "\t-r\twrite the config files under root instead of /, for a\n"
	    "\t\ttrial against copies. Use " BTMGR_SANDBOX ", never a\n"
	    "\t\tworld-writable directory: a sandbox copy of hcsecd.conf\n"
	    "\t\tcarries PINs and link keys.\n");
	exit(1);
}

static int
kq_add(int kq, uintptr_t ident, short filter, void *udata)
{
	struct kevent	kev;

	EV_SET(&kev, ident, filter, EV_ADD | EV_ENABLE, 0, 0, udata);

	return (kevent(kq, &kev, 1, NULL, 0, NULL));
}

static int
kq_del(int kq, uintptr_t ident, short filter)
{
	struct kevent	kev;

	EV_SET(&kev, ident, filter, EV_DELETE, 0, 0, NULL);

	/* Deleting something already gone is not worth reporting. */
	return (kevent(kq, &kev, 1, NULL, 0, NULL));
}

/*
 * Send a line to every client, dropping any that cannot take it.
 *
 * Note the saved next pointer. drop_client() frees c, so reading c->next
 * afterwards would be a use-after-free. This is the standard shape for
 * deleting from a linked list while walking it.
 */
static void
broadcast(struct daemon *d, const char *line)
{
	struct client	*c, *next;

	if (line == NULL)
		return;

	for (c = d->clients; c != NULL; c = next) {
		next = c->next;

		if (ipc_client_send(c, line) < 0) {
			drop_client(d, c);
			continue;
		}
		if (c->want_write)
			(void)kq_add(d->kq, (uintptr_t)c->fd, EVFILT_WRITE, c);
	}
}

static void
drop_client(struct daemon *d, struct client *c)
{
	struct client	**pp;

	(void)kq_del(d->kq, (uintptr_t)c->fd, EVFILT_READ);
	if (c->want_write)
		(void)kq_del(d->kq, (uintptr_t)c->fd, EVFILT_WRITE);

	/*
	 * Unlink. The pointer-to-pointer walk avoids a special case for
	 * removing the head, which is why C code does it this way.
	 */
	for (pp = &d->clients; *pp != NULL; pp = &(*pp)->next) {
		if (*pp == c) {
			*pp = c->next;
			break;
		}
	}

	/*
	 * Drop anything this client was waiting on. Without this, a
	 * completion arriving after it disconnected would dereference freed
	 * memory.
	 */
	inflight_drop_client(&d->pending, c);

	/*
	 * Same hazard for the parked pairing, and malloc reusing the address
	 * would make client_alive() hand this reply to an unrelated client.
	 * The pairing itself continues: the config is already written and the
	 * device may still deliver a key, so rolling back would lose it.
	 */
	if (d->pairing.client == c)
		d->pairing.client = NULL;

	ipc_client_free(c);
}

/*
 * Send a line the caller owns, free it, and drop the client if it could not
 * be queued. Folding the three together removes the repeated free-then-drop
 * dance every command handler would otherwise need.
 */
static void
reply(struct daemon *d, struct client *c, char *line)
{
	if (line == NULL)
		return;			/* allocation failed; say nothing */

	if (ipc_client_send(c, line) < 0) {
		free(line);
		drop_client(d, c);
		return;
	}
	free(line);

	if (c->want_write)
		(void)kq_add(d->kq, (uintptr_t)c->fd, EVFILT_WRITE, c);
}

/*
 * SPEC.md A5.3: state-changing commands require root or membership of the
 * socket's group. Read-only commands stay open to anyone who got past the
 * filesystem permissions.
 *
 * The supplementary group check is not optional. getpeereid() reports only
 * the peer's PRIMARY gid, but the kernel admits a connection on the strength
 * of any of the peer's groups. Checking the primary gid alone would therefore
 * refuse exactly the intended deployment, where the socket is group operator
 * and users are added to operator as a supplementary group.
 */
static int
may_change(const struct daemon *d, const struct client *c)
{
	struct passwd	*pw;
	struct group	*gr;
	int		 i;

	if (c->uid == 0)
		return (1);

	/*
	 * The socket's owner. In production that is root, already covered
	 * above; during development it is whoever started the daemon, which
	 * makes the -s override usable without a special case.
	 */
	if (d->sockuid != (uid_t)-1 && c->uid == d->sockuid)
		return (1);

	if (d->sockgid == (gid_t)-1)
		return (0);

	if (c->gid == d->sockgid)
		return (1);

	pw = getpwuid(c->uid);
	gr = getgrgid(d->sockgid);
	if (pw == NULL || gr == NULL || gr->gr_mem == NULL)
		return (0);

	for (i = 0; gr->gr_mem[i] != NULL; i++)
		if (strcmp(gr->gr_mem[i], pw->pw_name) == 0)
			return (1);

	return (0);
}

/*
 * SPEC.md B4.7. Listed by name rather than tested per handler so that a
 * command added later is covered by editing this list, not by remembering.
 * Four of these are not implemented yet.
 */
static int
blocked_while_pairing(const char *cmd)
{
	static const char *const blocked[] = {
		"pair", "remove", "set_alias", "set_trusted", "set_power"
	};
	size_t	 i;

	for (i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
		if (strcmp(cmd, blocked[i]) == 0)
			return (1);
	}

	return (0);
}

static struct pair_ops
pair_ops_for(struct daemon *d)
{
	struct pair_ops	 ops;

	ops.reload = hcsecd_ctl_reload;
	ops.hcsecd_running = hcsecd_ctl_running;
	ops.context = &d->hcsecd;

	return (ops);
}

/* A6 steps 6 and 7, on Link_Key_Notification for the device we are pairing. */
static void
finish_pairing(struct daemon *d, const bdaddr_t *addr)
{
	struct pair_ops		 ops = pair_ops_for(d);
	struct pair_report	 report;
	struct client		*c = d->pairing.client;
	enum pair_result	 r;
	int			 id = d->pairing.id;

	if (!d->pairing.state.active)
		return;
	if (memcmp(d->pairing.state.addr, addr, BTMGR_ADDR_LEN) != 0)
		return;			/* some other device's key */

	r = pairing_complete(&d->paths, &ops, &d->pairing.state,
	    d->pairing.name, NULL, (int64_t)time(NULL), &report);

	memset(&d->pairing, 0, sizeof(d->pairing));

	if (!client_alive(d, c))
		return;

	if (r == PAIR_DONE)
		reply(d, c, proto_ok(id));
	else
		reply(d, c, proto_error(id, "io_error",
		    report.detail[0] != '\0' ? report.detail : NULL));
}

/* A6.4 via pairing_abort: roll both config files back and tell the client. */
static void
abandon_pairing(struct daemon *d, const char *code, const char *why)
{
	struct pair_ops		 ops = pair_ops_for(d);
	struct pair_report	 report;
	struct client		*c = d->pairing.client;
	int			 id = d->pairing.id;
	uint16_t		 handle = d->pairing.handle;

	if (!d->pairing.state.active)
		return;

	(void)pairing_abort(&d->paths, &ops, &d->pairing.state, &report);
	memset(&d->pairing, 0, sizeof(d->pairing));

	/*
	 * Drop the link step 5 opened. A failed authentication leaves the ACL
	 * link up, and do_pair() refuses while one exists, so leaving it would
	 * block the retry. Any link here is ours for that same reason.
	 */
	if (handle != 0 && d->last.adapter_present)
		(void)btmgr_disconnect_start(d->last.adapter.node, handle,
		    BTMGR_REASON_USER);

	syslog(LOG_INFO, "pairing abandoned: %s", why);

	if (client_alive(d, c))
		reply(d, c, proto_error(id, code, why));
}

/*
 * A completion arrived on the passive listener. Match it against whoever
 * asked for it and answer them. This is the other half of the asynchronous
 * design: the reply to a connect request is delivered here, seconds after
 * the request itself was accepted.
 */
static void
on_completion(const struct listen_report *r, void *arg)
{
	struct daemon	*d = arg;
	struct inflight	*f;
	char		 detail[64];

	if (r->status != 0)
		(void)snprintf(detail, sizeof(detail),
		    "controller reported status 0x%02x", r->status);

	/*
	 * These two must return rather than fall through: the loop below reads
	 * "not a connection completion" as a disconnection, so either would be
	 * matched against the disconnect table by handle and silently consume
	 * someone's pending request.
	 */
	if (r->kind == LISTEN_LINK_KEY) {
		finish_pairing(d, &r->addr);
		return;
	}

	if (r->kind == LISTEN_AUTH_COMPL) {
		/*
		 * Success means the key is on its way, so there is nothing to
		 * do. Failure means it never will be, usually a refused or
		 * mistyped PIN.
		 */
		if (r->status != 0 && d->pairing.state.active &&
		    d->pairing.handle == r->handle)
			abandon_pairing(d, "io_error", detail);
		return;
	}

	if (r->kind == LISTEN_CON_COMPL && d->pairing.state.active &&
	    memcmp(d->pairing.state.addr, &r->addr, BTMGR_ADDR_LEN) == 0) {
		/*
		 * A6 step 5 is not done until the link is authenticated: a bare
		 * ACL link never exchanges a PIN, so no key would ever arrive.
		 * On failure abandon now, since waiting out the timeout would
		 * answer a page timeout with the unrelated "no link key".
		 */
		if (r->status != 0)
			abandon_pairing(d, "io_error", detail);
		else {
			d->pairing.handle = r->handle;
			if (btmgr_authenticate_start(d->last.adapter.node,
			    r->handle) < 0)
				abandon_pairing(d, "io_error",
				    "could not request authentication");
			else
				syslog(LOG_INFO, "authentication requested, "
				    "handle %u", r->handle);
		}
	}

	/*
	 * Loop, because more than one request can be waiting on the same
	 * device: two clients, or one client retrying. A single
	 * Connection_Complete is the answer to all of them, so fan it out.
	 * Answering only the first would leave the rest to time out twenty
	 * seconds later with "timeout" even though the connection succeeded.
	 */
	for (;;) {
		if (r->kind == LISTEN_CON_COMPL)
			f = inflight_take(&d->pending, INFLIGHT_CONNECT,
			    &r->addr);
		else
			f = inflight_take_handle(&d->pending,
			    INFLIGHT_DISCONNECT, r->handle);

		if (f == NULL)
			break;	/* nobody left waiting on this one */

		/* A client may have disconnected while we waited. */
		if (!client_alive(d, f->client))
			continue;

		if (r->status == 0)
			reply(d, f->client, proto_ok(f->id));
		else
			reply(d, f->client,
			    proto_error(f->id, "io_error", detail));
	}
}

/*
 * A6 steps 1 to 5. pairing_begin does 1 to 4 and parks; this then issues
 * Create_Connection, which is step 5 and the thing no caller was doing.
 */
static void
do_pair(struct daemon *d, struct client *c, const struct proto_cmd *cmd)
{
	struct pair_ops		 ops = pair_ops_for(d);
	struct pair_report	 report;
	enum pair_result	 r;

	int	 i;

	if (!cmd->has_addr) {
		reply(d, c, proto_error(cmd->id, "bad_addr",
		    "pair requires addr"));
		return;
	}

	/*
	 * Create_Connection on an open link produces no Connection_Complete at
	 * all, so step 5 would wait out the whole timeout and then blame a
	 * missing key. Being connected is not being paired: see B5.2.
	 */
	for (i = 0; i < d->last.nconns; i++) {
		if (bdaddr_same(&d->last.conns[i].bdaddr, &cmd->addr)) {
			reply(d, c, proto_error(cmd->id, "busy",
			    "already connected; disconnect before pairing"));
			return;
		}
	}

	r = pairing_begin(&d->paths, &ops, (const uint8_t *)&cmd->addr,
	    cmd->has_device_name ? cmd->device_name : NULL,
	    cmd->has_pin ? cmd->pin : NULL, &d->pairing.state, &report);

	switch (r) {
	case PAIR_NO_HCSECD:
		reply(d, c, proto_error(cmd->id, "hcsecd_unavailable",
		    report.detail));
		return;
	case PAIR_REFUSED:
		reply(d, c, proto_error(cmd->id, "not_permitted",
		    report.detail));
		return;
	case PAIR_ERROR:
		reply(d, c, proto_error(cmd->id, "hcsecd_config_error",
		    report.detail[0] != '\0' ? report.detail : NULL));
		return;
	case PAIR_PARKED:
		break;
	default:
		reply(d, c, proto_error(cmd->id, "io_error", NULL));
		return;
	}

	d->pairing.client = c;
	d->pairing.id = cmd->id;
	d->pairing.deadline = time(NULL) + PAIRING_TIMEOUT_SEC;
	if (cmd->has_device_name)
		(void)strlcpy(d->pairing.name, cmd->device_name,
		    sizeof(d->pairing.name));
	else
		d->pairing.name[0] = '\0';

	/* Step 5. A6.1: only now, with the block on disk and hcsecd reloaded. */
	if (btmgr_connect_start(d->last.adapter.node, &cmd->addr) < 0) {
		int	 saved = errno;

		/* B3.2 allows one reply, and abandon_pairing sends its own. */
		d->pairing.client = NULL;
		abandon_pairing(d, "io_error",
		    "could not start the connection");
		reply(d, c, proto_error(cmd->id, "io_error", strerror(saved)));
		return;
	}

	/* The reply comes from finish_pairing() when the key arrives. */
	syslog(LOG_INFO, "pairing started by uid %d", (int)c->uid);
}

/* A request outlived its deadline without a completion. */
static void
on_expired(const struct inflight *f, void *arg)
{
	struct daemon	*d = arg;

	if (!client_alive(d, f->client))
		return;

	reply(d, f->client, proto_error(f->id, "timeout",
	    "no completion from the controller"));
}

static void
handle_line(struct daemon *d, struct client *c, const char *line, size_t len)
{
	struct proto_cmd	 cmd;
	char			 code[32];

	if (proto_parse_cmd(line, len, &cmd, code, sizeof(code)) < 0) {
		reply(d, c, proto_error(cmd.id, code, NULL));
		return;
	}

	if (strcmp(cmd.name, "get_state") == 0) {
		/*
		 * Reply, then push the state itself. The ok says the request
		 * was understood; the event carries the payload, in the same
		 * shape it would arrive unsolicited.
		 */
		reply(d, c, proto_ok(cmd.id));
		if (!client_alive(d, c))
			return;
		reply(d, c, proto_state_event(&d->last));
		return;
	}

	/* Everything below changes state and needs the privilege check. */
	if (!may_change(d, c)) {
		reply(d, c, proto_error(cmd.id, "not_permitted",
		    "not root and not in the socket's group"));
		return;
	}

	if (!d->last.adapter_present) {
		reply(d, c, proto_error(cmd.id, "no_adapter", NULL));
		return;
	}

	/* SPEC.md B4.7. A reload now would drop the in-flight pairing. */
	if (d->pairing.state.active && blocked_while_pairing(cmd.name)) {
		reply(d, c, proto_error(cmd.id, "busy",
		    "a pairing is in progress"));
		return;
	}

	if (strcmp(cmd.name, "pair") == 0) {
		do_pair(d, c, &cmd);
		return;
	}

	if (strcmp(cmd.name, "connect") == 0) {
		if (!cmd.has_addr) {
			reply(d, c, proto_error(cmd.id, "bad_addr",
			    "connect requires addr"));
			return;
		}

		/*
		 * Park the request BEFORE sending, so a completion that
		 * arrives implausibly fast still finds someone waiting.
		 */
		if (inflight_add(&d->pending, INFLIGHT_CONNECT, cmd.id, c,
		    &cmd.addr, 0) < 0) {
			reply(d, c, proto_error(cmd.id, "busy",
			    "too many operations in flight"));
			return;
		}

		if (btmgr_connect_start(d->last.adapter.node, &cmd.addr) < 0) {
			(void)inflight_take(&d->pending, INFLIGHT_CONNECT,
			    &cmd.addr);
			reply(d, c, proto_error(cmd.id, "io_error",
			    strerror(errno)));
			return;
		}

		/* No reply yet: it comes from on_completion(). */
		syslog(LOG_INFO, "connect requested by uid %d", (int)c->uid);
		return;
	}

	if (strcmp(cmd.name, "disconnect") == 0) {
		uint16_t	handle = 0;
		int		i, found = 0;

		if (!cmd.has_addr) {
			reply(d, c, proto_error(cmd.id, "bad_addr",
			    "disconnect requires addr"));
			return;
		}

		/* The wire protocol speaks addresses; HCI wants a handle. */
		for (i = 0; i < d->last.nconns; i++) {
			if (bdaddr_same(&d->last.conns[i].bdaddr, &cmd.addr)) {
				handle = d->last.conns[i].handle;
				found = 1;
				break;
			}
		}
		if (!found) {
			reply(d, c, proto_error(cmd.id, "not_found",
			    "no connection to that address"));
			return;
		}

		if (inflight_add(&d->pending, INFLIGHT_DISCONNECT, cmd.id, c,
		    &cmd.addr, handle) < 0) {
			reply(d, c, proto_error(cmd.id, "busy", NULL));
			return;
		}

		if (btmgr_disconnect_start(d->last.adapter.node, handle,
		    BTMGR_REASON_USER) < 0) {
			(void)inflight_take_handle(&d->pending,
			    INFLIGHT_DISCONNECT, handle);
			reply(d, c, proto_error(cmd.id, "io_error",
			    strerror(errno)));
			return;
		}

		syslog(LOG_INFO, "disconnect requested by uid %d",
		    (int)c->uid);
		return;
	}

	if (strcmp(cmd.name, "set_discoverable") == 0) {
		int	on;

		/*
		 * The parser treats both fields as optional because other
		 * commands use them, so the handler has to insist. Without
		 * this, a request carrying neither silently turned
		 * discoverability OFF and reported success, changing adapter
		 * state on a malformed message.
		 */
		if (!cmd.has_timeout && !cmd.has_on) {
			reply(d, c, proto_error(cmd.id, "bad_json",
			    "set_discoverable requires timeout or on"));
			return;
		}

		/*
		 * Range check before any arithmetic. cmd.timeout * 1000 in an
		 * int overflows for values above about 2.1 million, which is
		 * undefined behaviour reached from a single client message.
		 * A negative timeout is equally a protocol error rather than
		 * something to reinterpret.
		 */
		if (cmd.has_timeout &&
		    (cmd.timeout < 0 || cmd.timeout > BTMGR_DISCOVER_MAX_SEC)) {
			reply(d, c, proto_error(cmd.id, "bad_json",
			    "timeout out of range"));
			return;
		}

		on = cmd.has_timeout ? (cmd.timeout > 0) : cmd.on;

		/*
		 * Page scan stays on. Turning it off would make us
		 * unreachable even to already-paired devices, which is not
		 * what a user means by "not discoverable".
		 */
		if (btmgr_set_scan(d->last.adapter.node, on, 1) < 0) {
			reply(d, c, proto_error(cmd.id, "io_error",
			    strerror(errno)));
			return;
		}

		/*
		 * A timeout re-arms the one-shot timer that turns it back
		 * off. EV_ONESHOT deletes the registration once it fires, so
		 * there is nothing to clean up afterwards.
		 */
		if (on && cmd.has_timeout && cmd.timeout > 0) {
			struct kevent	kev;
			int64_t		ms;

			/*
			 * Widen before multiplying. The range check above
			 * already bounds this, but doing the arithmetic in
			 * int64_t means the safety does not depend on
			 * remembering that.
			 */
			ms = (int64_t)cmd.timeout * 1000;

			EV_SET(&kev, 2, EVFILT_TIMER,
			    EV_ADD | EV_ENABLE | EV_ONESHOT, 0, ms,
			    &tag_discoverable);
			(void)kevent(d->kq, &kev, 1, NULL, 0, NULL);
		}

		d->dirty = 1;
		reply(d, c, proto_ok(cmd.id));
		return;
	}

	reply(d, c, proto_error(cmd.id, "not_found", "unknown command"));
}

static void
service_client(struct daemon *d, struct client *c)
{
	char	*line;
	size_t	 len;

	if (ipc_client_read(c) < 0) {
		drop_client(d, c);
		return;
	}

	while (ipc_client_line(c, &line, &len)) {
		handle_line(d, c, line, len);

		/*
		 * handle_line() may have dropped the client, in which case c
		 * is freed and we must not touch it again. Re-find it in the
		 * list to be sure it is still alive.
		 */
		if (!client_alive(d, c))
			return;
	}
}

/*
 * Is this client still in the list? Cheap because the list is tiny, and it is
 * the honest way to ask "did the thing I just called free my pointer".
 */
static int
client_alive(struct daemon *d, const struct client *c)
{
	const struct client	*p;

	for (p = d->clients; p != NULL; p = p->next)
		if (p == c)
			return (1);

	return (0);
}

static void
do_accept(struct daemon *d)
{
	struct client	*c;
	char		*hello, *st;

	for (;;) {
		c = ipc_accept(d->lfd);
		if (c == NULL) {
			if (errno == EAGAIN || errno == EINTR)
				return;
			syslog(LOG_ERR, "accept: %m");
			return;
		}

		c->next = d->clients;
		d->clients = c;

		if (kq_add(d->kq, (uintptr_t)c->fd, EVFILT_READ, c) < 0) {
			syslog(LOG_ERR, "kevent add client: %m");
			drop_client(d, c);
			continue;
		}

		/* SPEC.md B2: the greeting comes first, before anything else. */
		hello = proto_hello();
		if (hello != NULL) {
			(void)ipc_client_send(c, hello);
			free(hello);
		}

		/* Then the current state, so a client starts up in sync. */
		st = proto_state_event(&d->last);
		if (st != NULL) {
			(void)ipc_client_send(c, st);
			free(st);
		}

		if (c->want_write)
			(void)kq_add(d->kq, (uintptr_t)c->fd, EVFILT_WRITE, c);

		syslog(LOG_DEBUG, "client connected, uid %d", (int)c->uid);
	}
}

/*
 * Open or reopen the passive HCI socket to match the current adapter.
 *
 * Called whenever the adapter appears or goes away, which is how hotplug is
 * handled: devd has already built or torn down the netgraph stack by the time
 * we notice. See SPEC.md C3.
 */
static void
refresh_hci(struct daemon *d)
{
	const char	*want;

	want = d->last.adapter_present ? d->last.adapter.node : "";

	if (strcmp(d->node, want) == 0)
		return;			/* already matching */

	if (d->hci >= 0) {
		(void)kq_del(d->kq, (uintptr_t)d->hci, EVFILT_READ);
		listen_close(d->hci);
		d->hci = -1;
	}

	strlcpy(d->node, want, sizeof(d->node));

	if (want[0] == '\0') {
		syslog(LOG_INFO, "adapter gone");
		return;
	}

	d->hci = listen_open(want);
	if (d->hci < 0) {
		syslog(LOG_ERR, "listen_open %s: %m", want);
		d->node[0] = '\0';	/* retry on the next reconcile */
		return;
	}

	if (kq_add(d->kq, (uintptr_t)d->hci, EVFILT_READ, &tag_hci) < 0) {
		syslog(LOG_ERR, "kevent add hci: %m");
		listen_close(d->hci);
		d->hci = -1;
		d->node[0] = '\0';
		return;
	}

	syslog(LOG_INFO, "watching adapter %s", want);
}

/*
 * Rebuild the snapshot and tell clients only if it actually changed.
 *
 * SPEC.md B7.1. Rebuilding once per loop iteration rather than once per event
 * is what keeps a burst of three HCI events from producing three identical
 * broadcasts.
 */
static void
reconcile(struct daemon *d)
{
	struct state	 now;
	char		*line;

	state_snapshot(&now);

	if (d->have_last && state_equal(&now, &d->last)) {
		d->dirty = 0;
		return;
	}

	d->last = now;
	d->have_last = 1;
	d->dirty = 0;

	refresh_hci(d);

	line = proto_state_event(&d->last);
	if (line != NULL) {
		broadcast(d, line);
		free(line);
	}
}

int
main(int argc, char *argv[])
{
	struct daemon	 d;
	struct kevent	 events[MAX_EVENTS];
	struct client	*c;
	const char	*root = NULL;
	int		 ch, foreground = 0, dry_run = 0, i, n;

	memset(&d, 0, sizeof(d));
	d.kq = -1;
	d.lfd = -1;
	d.hci = -1;
	d.sockpath = DEFAULT_SOCKET;

	while ((ch = getopt(argc, argv, "fnr:s:")) != -1) {
		switch (ch) {
		case 'f':
			foreground = 1;
			break;
		case 'n':
			dry_run = 1;
			break;
		case 'r':
			root = optarg;
			break;
		case 's':
			d.sockpath = optarg;
			break;
		default:
			usage();
		}
	}
	if (optind != argc)
		usage();

	/*
	 * Resolve the config paths before anything else, so a bad -r is a
	 * startup error rather than a surprise at the first write. init()
	 * refuses a relative root and a world-writable one.
	 */
	if (btmgr_paths_init(&d.paths, root, dry_run) < 0)
		err(1, "config root '%s'", root != NULL ? root : "/");

	/* A8.1. uid 0 because a real hcsecd must be root to open the socket. */
	if (hcsecd_ctl_init(&d.hcsecd, NULL, 0, dry_run) < 0)
		err(1, "hcsecd_ctl_init");

	/*
	 * SPEC.md C4. A raw HCI write can return EPIPE unexpectedly, and a
	 * root daemon that dies on a signal because of it is unacceptable.
	 * Ignoring it turns the failure into an errno we can actually handle.
	 */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal SIGPIPE");

	/*
	 * EVFILT_SIGNAL does not replace the default disposition: without the
	 * SIG_IGN below, the process would still die on SIGTERM before kqueue
	 * ever reported it. Ignore first, then register.
	 */
	if (signal(SIGTERM, SIG_IGN) == SIG_ERR ||
	    signal(SIGINT, SIG_IGN) == SIG_ERR ||
	    signal(SIGHUP, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	openlog("bluetoothmgrd", LOG_PID | (foreground ? LOG_PERROR : 0),
	    LOG_DAEMON);

	d.kq = kqueue();
	if (d.kq < 0)
		err(1, "kqueue");

	d.lfd = ipc_listen(d.sockpath, SOCKET_MODE);
	if (d.lfd < 0)
		err(1, "ipc_listen %s", d.sockpath);

	if (kq_add(d.kq, (uintptr_t)d.lfd, EVFILT_READ, &tag_listen_sock) < 0)
		err(1, "kevent add listener");

	/*
	 * SPEC.md A5.3. Whoever shares the socket's group may change state.
	 * Reading it back from the socket rather than hardcoding a name means
	 * the -s override works for development without a special case.
	 */
	{
		struct stat	sb;

		d.sockuid = (uid_t)-1;
		d.sockgid = (gid_t)-1;
		if (stat(d.sockpath, &sb) == 0) {
			d.sockuid = sb.st_uid;
			d.sockgid = sb.st_gid;
		}
	}

	if (kq_add(d.kq, SIGTERM, EVFILT_SIGNAL, NULL) < 0 ||
	    kq_add(d.kq, SIGINT, EVFILT_SIGNAL, NULL) < 0 ||
	    kq_add(d.kq, SIGHUP, EVFILT_SIGNAL, NULL) < 0)
		err(1, "kevent add signals");

	/* EVFILT_TIMER data is milliseconds by default. */
	{
		struct kevent	kev;

		EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0,
		    RECONCILE_MS, &tag_timer);
		if (kevent(d.kq, &kev, 1, NULL, 0, NULL) < 0)
			err(1, "kevent add timer");
	}

	if (!foreground && daemon(0, 0) < 0)
		err(1, "daemon");

	syslog(LOG_INFO, "started, socket %s", d.sockpath);

	/* Prime the state before the first client can ask for it. */
	reconcile(&d);

	while (!d.quit) {
		n = kevent(d.kq, NULL, 0, events, MAX_EVENTS, NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			syslog(LOG_ERR, "kevent: %m");
			break;
		}

		for (i = 0; i < n; i++) {
			struct kevent	*ev = &events[i];

			if (ev->filter == EVFILT_SIGNAL) {
				if (ev->ident == SIGHUP) {
					syslog(LOG_INFO, "reload");
					d.dirty = 1;
				} else {
					syslog(LOG_INFO, "shutting down");
					d.quit = 1;
				}
				continue;
			}

			if (ev->udata == &tag_timer) {
				/*
				 * The tick doubles as the deadline check for
				 * in-flight operations, so no extra timer is
				 * needed for them.
				 */
				inflight_expire(&d.pending, time(NULL),
				    on_expired, &d);

				if (d.pairing.state.active &&
				    time(NULL) >= d.pairing.deadline)
					abandon_pairing(&d, "timeout",
					    "no link key arrived");

				d.dirty = 1;
				continue;
			}

			if (ev->udata == &tag_discoverable) {
				syslog(LOG_INFO, "discoverable timeout");
				if (d.last.adapter_present)
					(void)btmgr_set_scan(
					    d.last.adapter.node, 0, 1);
				d.dirty = 1;
				continue;
			}

			if (ev->udata == &tag_listen_sock) {
				do_accept(&d);
				continue;
			}

			if (ev->udata == &tag_hci) {
				int r = listen_drain(d.hci, on_completion, &d);

				if (r < 0) {
					syslog(LOG_ERR, "hci socket lost");
					(void)kq_del(d.kq, (uintptr_t)d.hci,
					    EVFILT_READ);
					listen_close(d.hci);
					d.hci = -1;
					d.node[0] = '\0';
					d.dirty = 1;
				} else if (r > 0) {
					d.dirty = 1;
				}
				continue;
			}

			/* Anything else is a client. */
			c = ev->udata;
			if (c == NULL)
				continue;

			if (ev->filter == EVFILT_WRITE) {
				if (ipc_client_flush(c) < 0) {
					drop_client(&d, c);
					continue;
				}
				if (!c->want_write)
					(void)kq_del(d.kq, (uintptr_t)c->fd,
					    EVFILT_WRITE);
				continue;
			}

			if (ev->filter == EVFILT_READ) {
				service_client(&d, c);
				continue;
			}
		}

		/*
		 * Coalesce: whatever happened above, rebuild and broadcast at
		 * most once per iteration.
		 */
		if (d.dirty)
			reconcile(&d);
	}

	while (d.clients != NULL)
		drop_client(&d, d.clients);

	if (d.hci >= 0)
		listen_close(d.hci);
	if (d.lfd >= 0)
		close(d.lfd);
	(void)unlink(d.sockpath);		/* SPEC.md A5.2 */
	if (d.kq >= 0)
		close(d.kq);

	syslog(LOG_INFO, "stopped");
	closelog();

	return (0);
}
