/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * devd.c - ubt attach and detach from devd's event socket. SPEC.md C3.4.
 *
 * devd writes one message per event, "+ubt0 at ... on uhub1" for an attach
 * and "-ubt0 at ..." for a detach. Everything else is ignored.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "devd.h"

#define	DEVD_SOCKET	"/var/run/devd.seqpacket.pipe"
#define	DEVD_UNIT_MAX	255

static int	ubt_unit(const char *name);

/* The unit of "ubtN", or -1 for any other device name. */
static int
ubt_unit(const char *name)
{
	const char	*digit;
	int		 unit = 0;

	if (strncmp(name, "ubt", 3) != 0)
		return (-1);

	digit = name + 3;
	if (*digit < '0' || *digit > '9')
		return (-1);

	for (; *digit >= '0' && *digit <= '9'; digit++) {
		unit = unit * 10 + (*digit - '0');
		if (unit > DEVD_UNIT_MAX)
			return (-1);
	}

	if (*digit != ' ' && *digit != '\0')
		return (-1);

	return (unit);
}

int
devd_open(void)
{
	struct sockaddr_un	address;
	int			fd, saved;

	fd = socket(PF_LOCAL, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_LOCAL;
	(void)strlcpy(address.sun_path, DEVD_SOCKET, sizeof(address.sun_path));

	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}

	return (fd);
}

int
devd_drain(int fd, void (*cb)(enum devd_event event, int unit, void *arg),
    void *arg)
{
	char	message[1024];
	ssize_t	length;
	int	unit;

	for (;;) {
		length = recv(fd, message, sizeof(message) - 1, 0);
		if (length < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return (0);
			return (-1);
		}
		if (length == 0)
			return (-1);

		message[length] = '\0';

		if (message[0] != '+' && message[0] != '-')
			continue;

		unit = ubt_unit(message + 1);
		if (unit < 0)
			continue;

		cb(message[0] == '+' ? DEVD_ATTACH : DEVD_DETACH, unit, arg);
	}
}
