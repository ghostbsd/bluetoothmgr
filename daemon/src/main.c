/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * bluetoothmgrd - BluetoothMgr daemon.
 *
 * One kqueue loop watching five kinds of thing at once: the listening socket,
 * each connected client's readability and writability, the passive HCI event
 * socket, signals, and a periodic reconcile timer.
 *
 * M2 performs no privileged operation at all. Per PLAN.md F2 the entire
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

#include "inflight.h"
#include "ipc.h"
#include "listen.h"
#include "proto.h"
#include "state.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

#define	DEFAULT_SOCKET	"/var/run/bluetoothmgr.sock"
#define	SOCKET_MODE	0660
#define	RECONCILE_MS	5000		/* PLAN.md 4.4: the safety net */

/*
 * Upper bound on a discoverability timeout, one hour. Bluetooth UIs offer
 * minutes, so this is generous; its job is to keep a client from reaching
 * integer overflow in the millisecond conversion.
 */
#define	BTMGR_DISCOVER_MAX_SEC	3600
#define	MAX_EVENTS	32

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
	struct inflight_table	pending;
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
static void	on_completion(const struct listen_report *r, void *arg);
static void	on_expired(const struct inflight *f, void *arg);

static void
usage(void)
{
	fprintf(stderr, "usage: bluetoothmgrd [-f] [-s socket]\n");
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
		snprintf(detail, sizeof(detail),
		    "controller reported status 0x%02x", r->status);

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
 * we notice. See PLAN.md F5.
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
	int		 ch, foreground = 0, i, n;

	memset(&d, 0, sizeof(d));
	d.kq = -1;
	d.lfd = -1;
	d.hci = -1;
	d.sockpath = DEFAULT_SOCKET;

	while ((ch = getopt(argc, argv, "fs:")) != -1) {
		switch (ch) {
		case 'f':
			foreground = 1;
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
	 * PLAN.md F8. A raw HCI write can return EPIPE unexpectedly, and a
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