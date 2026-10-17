/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * session.h - is this peer allowed on the socket? SPEC.md A5.3, A9.
 *
 * The test is on the peer process, not its user. A9.4: someone at the GUI who
 * also logs in over ssh presents the same uid on both connections, so a uid
 * comparison would authorize the ssh one.
 *
 * The two record predicates are public because the on-disk utmpx format is
 * private to libc, so a test cannot write a fixture for setutxdb() to read.
 * They take a struct utmpx the caller can build in memory instead.
 */

#ifndef BTMGR_SESSION_H_
#define	BTMGR_SESSION_H_

#include <sys/types.h>
#include <sys/time.h>

struct utmpx;

/*
 * How far up the parent chain to look for the session leader. A desktop puts a
 * handful of processes between a session leader and an application; the bound
 * is only here so a malformed chain cannot loop forever.
 */
#define	BTMGR_SESSION_MAX_DEPTH	64

/*
 * Non-zero when the peer may use the socket: root, or a process descended from
 * the leader of an active GUI session. Zero otherwise, including every case
 * where the answer could not be determined, per A9.6.
 */
int	btmgr_session_peer_allowed(uid_t peer_uid, pid_t peer_pid);

/* Non-zero if pid is ancestor, or descends from it. */
int	btmgr_session_descends_from(pid_t pid, pid_t ancestor);

/* A9.2. */
int	btmgr_session_record_is_gui(const struct utmpx *ut);

/* A9.5, and the record's leader must run as peer_uid. */
int	btmgr_session_leader_matches(const struct utmpx *ut, uid_t peer_uid);

/* A5.4. Taken at accept, checked again later, since pids are reused. */
int	btmgr_session_peer_start(pid_t pid, struct timeval *out);

/*
 * Read the utmpx database from path instead of /var/run/utx.active. For tests
 * only. NULL restores the default.
 */
void	btmgr_session_set_db(const char *path);

#endif
