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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "ipc.h"
#include "listen.h"
#include "proto.h"
#include "state.h"

/* Must come after the system headers: it redefines malloc and friends. */
#include "memcheck.h"

#define	DEFAULT_SOCKET	"/var/run/bluetoothmgr.sock"
#define	SOCKET_MODE	0660
#define	RECONCILE_MS	5000		/* PLAN.md 4.4: the safety net */
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

	ipc_client_free(c);
}

static void
handle_line(struct daemon *d, struct client *c, const char *line, size_t len)
{
	struct proto_cmd	 cmd;
	char			 code[32];
	char			*reply = NULL;

	if (proto_parse_cmd(line, len, &cmd, code, sizeof(code)) < 0) {
		reply = proto_error(cmd.id, code, NULL);
	} else if (strcmp(cmd.name, "get_state") == 0) {
		/*
		 * Reply, then push the state itself. The ok tells the client
		 * its request was understood; the event carries the payload,
		 * in the same shape it would arrive unsolicited.
		 */
		reply = proto_ok(cmd.id);
		if (reply != NULL && ipc_client_send(c, reply) < 0) {
			free(reply);
			drop_client(d, c);
			return;
		}
		free(reply);

		reply = proto_state_event(&d->last);
	} else {
		reply = proto_error(cmd.id, "not_found", "unknown command");
	}

	if (reply == NULL)
		return;			/* allocation failed, say nothing */

	if (ipc_client_send(c, reply) < 0) {
		free(reply);
		drop_client(d, c);
		return;
	}
	free(reply);

	if (c->want_write)
		(void)kq_add(d->kq, (uintptr_t)c->fd, EVFILT_WRITE, c);
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
				d.dirty = 1;
				continue;
			}

			if (ev->udata == &tag_listen_sock) {
				do_accept(&d);
				continue;
			}

			if (ev->udata == &tag_hci) {
				int r = listen_drain(d.hci);

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