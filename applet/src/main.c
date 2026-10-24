/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * bluetoothmgr-applet - the MATE panel applet. PLAN.md M6.
 *
 * In process: a module the panel loads, so a crash here takes the panel with
 * it. Out of process would be safer, but the panel launches such an applet
 * through D-Bus activation, which leaves it in the session bus's session
 * rather than the desktop's, and A5.3 then refuses it.
 *
 * common/ipc_client.c owns no event loop, so the fd goes to GLib here.
 */

#include <mate-panel-applet.h>
#include <glib-unix.h>

#include "ipc_client.h"
#include "proto.h"

/* Breathing room so the icon does not touch the panel edges. */
#define	ICON_PADDING	4

/* How often to retry a daemon that is not running, in seconds. */
#define	RETRY_SECONDS	5

/*
 * common/ipc_client.c only expires a request from inside its dispatch, which
 * runs when the fd is readable. A daemon that accepts the probe and then goes
 * quiet never makes it readable, so the deadline needs a timer of its own.
 */
#define	EXPIRY_SECONDS	(BTMGR_REQUEST_TIMEOUT_SEC + 1)

enum applet_state {
	APPLET_ABSENT = 0,	/* no adapter, or no daemon */
	APPLET_OFF,		/* adapter present, stack down */
	APPLET_ON,		/* stack up, nothing connected */
	APPLET_CONNECTED
};

struct applet_ui {
	MatePanelApplet		*applet;
	GtkWidget		*icon;
	struct btmgr_ipc	*conn;
	guint			 watch;		/* fd source, 0 when none */
	guint			 retry;		/* timer source, 0 when none */
	guint			 expiry;	/* probe deadline, 0 when none */
	int			 asked;		/* get_state already sent */
	int			 probe_failed;	/* act once dispatch has returned */
	char			 failure[128];	/* why, for the tooltip */
	enum applet_state	 state;
};

static const char *state_icon(enum applet_state state);
static void	 size_icon(MatePanelApplet *applet, GtkWidget *icon);
static void	 set_state(struct applet_ui *ui, enum applet_state state,
		     const char *detail);
static void	 disconnect(struct applet_ui *ui, const char *why);
static void	 ask_state(struct applet_ui *ui);
static void	 on_reply(const struct proto_msg *reply, void *data);
static void	 on_event(const struct proto_msg *event, void *data);
static gboolean	 on_readable(gint fd, GIOCondition cond, gpointer data);
static gboolean	 on_retry(gpointer data);
static gboolean	 on_expiry(gpointer data);
static void	 connect_daemon(struct applet_ui *ui);
static void	 on_change_size(MatePanelApplet *applet, guint size,
		     gpointer data);
static void	 on_destroy(GtkWidget *widget, gpointer data);
static gboolean	 applet_fill(MatePanelApplet *applet, const gchar *iid,
		     gpointer data);

/*
 * A name the theme lacks renders broken rather than falling back, and
 * Qogir-Dark has only "bluetooth", so every list ends there.
 */
static const char *const icons_absent[] = {
	"bluetooth-hardware-disabled-symbolic",
	"bluetooth-disconnected-symbolic",
	"bluetooth-disabled",
	"bluetooth",
	NULL
};

static const char *const icons_off[] = {
	"bluetooth-disabled",
	"bluetooth-disabled-symbolic",
	"bluetooth-inactive",
	"bluetooth",
	NULL
};

static const char *const icons_on[] = {
	"bluetooth",
	"bluetooth-symbolic",
	NULL
};

static const char *const icons_connected[] = {
	"bluetooth-active",
	"bluetooth-active-symbolic",
	"bluetooth-paired",
	"bluetooth",
	NULL
};

static const char *
state_icon(enum applet_state state)
{
	const char *const	*names;
	GtkIconTheme		*theme;
	int			 i;

	switch (state) {
	case APPLET_OFF:
		names = icons_off;
		break;
	case APPLET_ON:
		names = icons_on;
		break;
	case APPLET_CONNECTED:
		names = icons_connected;
		break;
	case APPLET_ABSENT:
	default:
		names = icons_absent;
		break;
	}

	theme = gtk_icon_theme_get_default();
	for (i = 0; names[i + 1] != NULL; i++)
		if (gtk_icon_theme_has_icon(theme, names[i]))
			return (names[i]);

	/* The last is taken whether the theme has it or not. */
	return (names[i]);
}

static void
size_icon(MatePanelApplet *applet, GtkWidget *icon)
{
	guint	 size;

	size = mate_panel_applet_get_size(applet);
	if (size > ICON_PADDING)
		size -= ICON_PADDING;

	gtk_image_set_pixel_size(GTK_IMAGE(icon), (gint)size);
}

/* detail becomes the tooltip, so a refusal does not look like a dead icon. */
static void
set_state(struct applet_ui *ui, enum applet_state state, const char *detail)
{

	ui->state = state;
	gtk_image_set_from_icon_name(GTK_IMAGE(ui->icon), state_icon(state),
	    GTK_ICON_SIZE_MENU);
	size_icon(ui->applet, ui->icon);

	/* Dimmed: off and absent must still differ on a one-icon theme. */
	gtk_widget_set_sensitive(ui->icon,
	    state == APPLET_ON || state == APPLET_CONNECTED);

	gtk_widget_set_tooltip_text(GTK_WIDGET(ui->applet), detail);
}

static void
disconnect(struct applet_ui *ui, const char *why)
{

	if (ui->watch != 0) {
		g_source_remove(ui->watch);
		ui->watch = 0;
	}
	if (ui->expiry != 0) {
		g_source_remove(ui->expiry);
		ui->expiry = 0;
	}
	if (ui->conn != NULL) {
		btmgr_ipc_close(ui->conn);
		ui->conn = NULL;
	}
	ui->asked = 0;
	ui->probe_failed = 0;

	set_state(ui, APPLET_ABSENT, why);

	if (ui->retry == 0)
		ui->retry = g_timeout_add_seconds(RETRY_SECONDS, on_retry, ui);
}

/*
 * B2.1 makes the daemon speak first, so a request before the hello is refused
 * with ENOTCONN. Sent once the handshake has landed, and only to learn whether
 * A5.3 admits us: the state arrives unasked when it does.
 */
static void
ask_state(struct applet_ui *ui)
{
	struct proto_cmd	 cmd;

	if (ui->asked || !btmgr_ipc_is_ready(ui->conn))
		return;

	memset(&cmd, 0, sizeof(cmd));
	(void)strlcpy(cmd.name, "get_state", sizeof(cmd.name));

	if (btmgr_ipc_request(ui->conn, &cmd, on_reply, ui) != 0)
		return;

	ui->asked = 1;
	if (ui->expiry == 0)
		ui->expiry = g_timeout_add_seconds(EXPIRY_SECONDS, on_expiry, ui);
}

/*
 * Cannot close the connection here: ipc_client.h forbids it from a callback,
 * because the dispatch loop is still walking this connection. The caller
 * disconnects once it has returned, which puts the retry back on one path.
 */
static void
on_reply(const struct proto_msg *reply, void *data)
{
	struct applet_ui	*ui = data;
	const char		*why;

	if (reply->succeeded)
		return;

	/* A5.3. Worth saying out loud: the icon alone cannot show it. */
	why = reply->error_detail[0] != '\0' ? reply->error_detail :
	    reply->error_code;

	(void)g_strlcpy(ui->failure, why, sizeof(ui->failure));
	ui->probe_failed = 1;

	set_state(ui, APPLET_ABSENT, ui->failure);
}

static void
on_event(const struct proto_msg *event, void *data)
{
	struct applet_ui	*ui = data;
	enum applet_state	 state;

	if (!event->has_state)
		return;

	if (!event->state.adapter_present)
		state = APPLET_ABSENT;
	else if (!event->state.powered)
		state = APPLET_OFF;
	else if (event->state.connection_count > 0)
		state = APPLET_CONNECTED;
	else
		state = APPLET_ON;

	set_state(ui, state, state == APPLET_ABSENT ?
	    "No Bluetooth adapter" : "Bluetooth");
}

static gboolean
on_readable(gint fd, GIOCondition cond, gpointer data)
{
	struct applet_ui	*ui = data;

	(void)fd;

	if ((cond & (G_IO_HUP | G_IO_ERR)) != 0) {
		ui->watch = 0;			/* returning REMOVE frees it */
		disconnect(ui, "Lost the BluetoothMgr daemon");
		return (G_SOURCE_REMOVE);
	}

	if (btmgr_ipc_fill(ui->conn) < 0 ||
	    btmgr_ipc_dispatch(ui->conn, on_event, ui) < 0) {
		ui->watch = 0;
		disconnect(ui, "Lost the BluetoothMgr daemon");
		return (G_SOURCE_REMOVE);
	}

	/*
	 * A refusal is not permanent: it reflects whether our session was
	 * recognised at the moment we asked. Reconnecting re-probes it.
	 */
	if (ui->probe_failed) {
		ui->watch = 0;
		disconnect(ui, ui->failure);
		return (G_SOURCE_REMOVE);
	}

	ask_state(ui);

	return (G_SOURCE_CONTINUE);
}

static gboolean
on_retry(gpointer data)
{
	struct applet_ui	*ui = data;

	ui->retry = 0;
	connect_daemon(ui);

	return (G_SOURCE_REMOVE);
}

static gboolean
on_expiry(gpointer data)
{
	struct applet_ui	*ui = data;

	/* Cleared first: disconnect() must not remove a source mid-callback. */
	ui->expiry = 0;

	/* expire_requests() calls on_reply, so the flag is set by now. */
	if (btmgr_ipc_expire_requests(ui->conn) > 0 && ui->probe_failed)
		disconnect(ui, ui->failure);

	return (G_SOURCE_REMOVE);
}

static void
connect_daemon(struct applet_ui *ui)
{

	ui->conn = btmgr_ipc_open(NULL);
	if (ui->conn == NULL) {
		disconnect(ui, "BluetoothMgr is not running");
		return;
	}

	/* poll reports HUP and ERR whether or not they were asked for. */
	ui->watch = g_unix_fd_add(btmgr_ipc_fd(ui->conn), G_IO_IN,
	    on_readable, ui);
}

static void
on_change_size(MatePanelApplet *applet, guint size, gpointer data)
{
	struct applet_ui	*ui = data;

	(void)size;
	size_icon(applet, ui->icon);
}

static void
on_destroy(GtkWidget *widget, gpointer data)
{
	struct applet_ui	*ui = data;

	(void)widget;

	if (ui->retry != 0)
		g_source_remove(ui->retry);
	if (ui->watch != 0)
		g_source_remove(ui->watch);
	if (ui->expiry != 0)
		g_source_remove(ui->expiry);
	if (ui->conn != NULL)
		btmgr_ipc_close(ui->conn);

	g_free(ui);
}

static gboolean
applet_fill(MatePanelApplet *applet, const gchar *iid, gpointer data)
{
	struct applet_ui	*ui;

	(void)data;

	/* The panel asks one factory for every applet it provides. */
	if (g_strcmp0(iid, "BluetoothMgrApplet") != 0)
		return (FALSE);

	ui = g_new0(struct applet_ui, 1);
	ui->applet = applet;
	ui->icon = gtk_image_new_from_icon_name(state_icon(APPLET_ABSENT),
	    GTK_ICON_SIZE_MENU);

	gtk_container_add(GTK_CONTAINER(applet), ui->icon);

	/* So the applet follows a panel with a background image or colour. */
	mate_panel_applet_set_background_widget(applet, GTK_WIDGET(applet));

	g_signal_connect(applet, "change-size", G_CALLBACK(on_change_size), ui);
	g_signal_connect(applet, "destroy", G_CALLBACK(on_destroy), ui);

	set_state(ui, APPLET_ABSENT, "Connecting to BluetoothMgr");
	connect_daemon(ui);

	gtk_widget_show_all(GTK_WIDGET(applet));

	return (TRUE);
}

MATE_PANEL_APPLET_IN_PROCESS_FACTORY("BluetoothMgrAppletFactory",
    PANEL_TYPE_APPLET, "BluetoothMgr", applet_fill, NULL)
