/*
 * Copyright (C) 2014  Miroslav Lichvar <mlichvar@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/rtc.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gio/gio.h>

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include "timedated.h"

#define NTP_UNITS_PATHS "/etc/systemd/ntp-units.d:/usr/lib/systemd/ntp-units.d"
#define QUIT_TIMEOUT 30

#define ADJTIME_PATH "/etc/adjtime"
#define HWCLOCK_PATH "/sbin/hwclock"
#define RTC_DEVICE "/dev/rtc"

#define LOCALTIME_PATH "/etc/localtime"
#define ZONEINFO_PATH "/usr/share/zoneinfo/"
#define LOCALTIME_TO_ZONEINFO_PATH ".."
#define MAX_TIMEZONE_LENGTH 256

#define TIMEDATED_NAME "org.freedesktop.timedate1"
#define TIMEDATED_PATH "/org/freedesktop/timedate1"
#define TIMEDATED_INTERFACE "org.freedesktop.timedate1"
#define PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"

#define SYSTEMD_NAME "org.freedesktop.systemd1"
#define SYSTEMD_PATH "/org/freedesktop/systemd1"
#define SYSTEMD_MANAGER_INTERFACE "org.freedesktop.systemd1.Manager"
#define SYSTEMD_UNIT_INTERFACE "org.freedesktop.systemd1.Unit"

#define POLKIT_NAME "org.freedesktop.PolicyKit1"
#define POLKIT_PATH "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_INTERFACE "org.freedesktop.PolicyKit1.Authority"
#define POLKIT_ACTION_SET_TIME "org.freedesktop.timedate1.set-time"
#define POLKIT_ACTION_SET_NTP_ACTIVE "org.freedesktop.timedate1.set-ntp"
#define POLKIT_ACTION_SET_RTC_LOCAL "org.freedesktop.timedate1.set-local-rtc"
#define POLKIT_ACTION_SET_TIMEZONE "org.freedesktop.timedate1.set-timezone"
#define POLKIT_AUTH_CHECK_TIMEOUT 20

/* This may be missing in libc headers */
#ifndef ADJ_SETOFFSET
#define ADJ_SETOFFSET 0x0100
#endif

struct ntp_unit {
	gchar *name;
	gchar *sort_name;
};

struct method_call_data {
	union {
		struct {
			gchar timezone[MAX_TIMEZONE_LENGTH + 1];
		} set_timezone;
		struct {
			gint64 request_time;
			gint64 requested_time;
			gboolean relative;
		} set_time;
		struct {
			gboolean local;
			gboolean adjust_system;
		} set_rtc_local;
		struct {
			gboolean active;
		} set_ntp_active;
	};
};

typedef void (*auth_check_handler)(GDBusMethodInvocation *invocation, struct method_call_data *handler_data);

struct auth_check {
	GCancellable *cancellable;
	guint cancel_id;
	gchar *cancel_string;
	GDBusMethodInvocation *invocation;
	auth_check_handler handler;
	struct method_call_data *handler_data;
};

typedef void (*hwclock_call_handler)(GDBusMethodInvocation *invocation, struct method_call_data *handler_data);

struct hwclock_call {
	GDBusMethodInvocation *invocation;
	hwclock_call_handler handler;
	struct method_call_data *handler_data;
};


/* Global variables */
static GDBusProxy *systemd_proxy, *polkit_proxy;
static gboolean main_quit, running_auth_checks;
static GArray *ntp_units;


static void return_success(GDBusMethodInvocation *invocation) {
	g_dbus_method_invocation_return_value(invocation, g_variant_new("()"));
}

static void return_error(GDBusMethodInvocation *invocation, gint code, const gchar *format, ...) {
	va_list va;

	va_start(va, format);
	g_dbus_method_invocation_return_error_valist(invocation, G_DBUS_ERROR, code, format, va);
	va_end(va);
}

static GDBusProxy *get_bus_proxy(const gchar *name, const gchar *path, const gchar *interface) {
	GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE, NULL,
					      name, path, interface, NULL, &error);
	if (!proxy) {
		g_printerr("Failed to create %s proxy: %s\n", name, error->message);
		g_error_free(error);
	}

	return proxy;
}

static GVariant *get_object_property(const gchar *name, const gchar *path, const gchar *interface,
				     const gchar *property) {
	GDBusProxy *proxy;
	GVariant *ret;

	proxy = get_bus_proxy(name, path, interface);
	if (!proxy)
		return NULL;

	ret = g_dbus_proxy_get_cached_property(proxy, property);
	g_object_unref(proxy);

	return ret;
}

static void emit_property_change(GDBusConnection *connection, const gchar *name, GVariant *value) {
	GVariantBuilder builder;
	const gchar *invalidated = { NULL };

	g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&builder, "{sv}", name, value);
	g_dbus_connection_emit_signal(connection, NULL, TIMEDATED_PATH, PROPERTIES_INTERFACE,
				      "PropertiesChanged",
				      g_variant_new("(sa{sv}^as)", TIMEDATED_INTERFACE,
						    &builder, &invalidated),
				      NULL);
}

static void finish_auth_check(GObject *source_object, GAsyncResult *res, gpointer user_data) {
	GError *error = NULL;
	GVariant *result;
	gboolean authorized;
	struct auth_check *auth_check = user_data;

	if (auth_check->cancel_id)
		g_source_remove(auth_check->cancel_id);
	g_free(auth_check->cancel_string);

	result = g_dbus_proxy_call_finish(polkit_proxy, res, &error);
	if (!result) {
		g_dbus_error_strip_remote_error(error);
		g_printerr("Failed to check authorization: %s\n", error->message);
		g_error_free(error);
		authorized = FALSE;
	} else {
		g_variant_get(result, "((bba{ss}))", &authorized, NULL, NULL);
		g_variant_unref(result);
	}

	if (authorized) {
		(auth_check->handler)(auth_check->invocation, auth_check->handler_data);
	} else {
		return_error(auth_check->invocation, G_DBUS_ERROR_AUTH_FAILED, "Not authorized");
	}

	g_object_unref(auth_check->cancellable);
	g_free(auth_check->handler_data);
	g_free(auth_check);

	g_assert(running_auth_checks);
	running_auth_checks--;
}

static gboolean cancel_auth_check(gpointer user_data) {
	GError *error = NULL;
	GVariant *result;
	struct auth_check *auth_check = user_data;

	g_cancellable_cancel(auth_check->cancellable);

	result = g_dbus_proxy_call_sync(polkit_proxy, "CancelCheckAuthorization",
					g_variant_new("(s)", auth_check->cancel_string),
					G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (!result) {
		g_dbus_error_strip_remote_error(error);
		g_printerr("Failed to cancel authorization check: %s\n", error->message);
		g_error_free(error);
	} else {
		g_variant_unref(result);
	}

	auth_check->cancel_id = 0;

	/* Destroy the timeout */
	return FALSE;
}

static void start_auth_check(const gchar *name, const gchar *action, gboolean user_interaction,
			     GDBusMethodInvocation *invocation, auth_check_handler handler,
			     struct method_call_data *handler_data) {
	GVariant *parameters;
	GVariantBuilder builder1, builder2;
	struct auth_check *auth_check;

	auth_check = g_new(struct auth_check, 1);
	auth_check->cancellable = g_cancellable_new();
	auth_check->cancel_id = g_timeout_add(POLKIT_AUTH_CHECK_TIMEOUT * 1000, cancel_auth_check, auth_check);
	auth_check->cancel_string = g_malloc(30);
	auth_check->invocation = invocation;
	auth_check->handler = handler;
	auth_check->handler_data = (struct method_call_data *)g_memdup(handler_data, sizeof *handler_data);

	snprintf(auth_check->cancel_string, 30, "cancel%u", auth_check->cancel_id);

	g_variant_builder_init(&builder1, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&builder1, "{sv}", "name", g_variant_new_string(name));

	g_variant_builder_init(&builder2, G_VARIANT_TYPE("a{ss}"));

	parameters = g_variant_new("((sa{sv})sa{ss}us)", "system-bus-name", &builder1,
				   action, &builder2, user_interaction ? 1 : 0, auth_check->cancel_string);

	g_dbus_proxy_call(polkit_proxy, "CheckAuthorization", parameters,
			  G_DBUS_CALL_FLAGS_NONE, -1, NULL, finish_auth_check, auth_check);

	running_auth_checks++;
}

static GVariant *call_systemd(const char *method_name, GVariant *parameters) {
	GError *error = NULL;
	GVariant *result;

	result = g_dbus_proxy_call_sync(systemd_proxy, method_name, parameters,
					G_DBUS_CALL_FLAGS_NONE, -1, NULL, &error);
	if (!result) {
		g_dbus_error_strip_remote_error(error);
		g_printerr("systemd method %s failed: %s\n", method_name, error->message);
		g_error_free(error);
		return NULL;
	}

	return result;
}

static gboolean call_systemd_noresult(const char *method_name, GVariant *parameters) {
	GVariant *result;

	result = call_systemd(method_name, parameters);
	if (result) {
		g_variant_unref(result);
		return TRUE;
	}

	return FALSE;
}

static void finish_hwclock_call(GPid pid, gint status, gpointer user_data) {
	struct hwclock_call *hwclock_call = user_data;
	GError *error = NULL;

	g_spawn_close_pid(pid);

	if (g_spawn_check_exit_status(status, &error)) {
		if (hwclock_call->handler)
			(hwclock_call->handler)(hwclock_call->invocation, hwclock_call->handler_data);
	} else {
		g_printerr("hwclock failed: %s\n", error->message);
		if (hwclock_call->invocation)
			return_error(hwclock_call->invocation, G_DBUS_ERROR_FAILED, "hwclock failed: %s",
				     error->message);
		g_error_free(error);
	}

	g_free(hwclock_call->handler_data);
	g_free(hwclock_call);
}

static void start_hwclock_call(gboolean hctosys, gboolean local, gboolean utc,
			       GDBusMethodInvocation *invocation, hwclock_call_handler handler,
			       struct method_call_data *handler_data) {
	char *argv[8] = { 0 };
	int argc = 0;
	GPid pid;
	GError *error = NULL;
	struct hwclock_call *hwclock_call;

	argv[argc++] = HWCLOCK_PATH;
	argv[argc++] = "-f";
	argv[argc++] = RTC_DEVICE;
	argv[argc++] = hctosys ? "--hctosys" : "--systohc";
	if (local)
		argv[argc++] = "--local";
	if (utc)
		argv[argc++] = "--utc";

	if (!g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL |
			   G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL, &pid, &error)) {
		g_printerr("%s\n", error->message);
		if (invocation)
			return_error(invocation, G_DBUS_ERROR_FAILED, "%s", error->message);
		g_error_free(error);
		return;
	}

	hwclock_call = g_new(struct hwclock_call, 1);
	hwclock_call->invocation = invocation;
	hwclock_call->handler = handler;
	hwclock_call->handler_data = (struct method_call_data *)g_memdup(handler_data, sizeof *handler_data);

	g_child_watch_add(pid, finish_hwclock_call, hwclock_call);
}

static struct ntp_unit *get_ntp_unit(guint index) {
	return &g_array_index(ntp_units, struct ntp_unit, index);
}

static void free_ntp_units(void) {
	guint i;

	if (!ntp_units)
		return;

	for (i = 0; i < ntp_units->len; i++) {
		g_free(get_ntp_unit(i)->name);
		g_free(get_ntp_unit(i)->sort_name);
	}

	g_array_free(ntp_units, TRUE);
	ntp_units = NULL;
}

gint compare_ntp_units(gconstpointer a, gconstpointer b) {
	return g_strcmp0(((struct ntp_unit *)a)->sort_name, ((struct ntp_unit *)b)->sort_name);
}

static void read_ntp_units(void) {
	gchar path[PATH_MAX], **unit_dir, **unit_dirs, *contents, **lines, **line;
	const gchar *entry;
	struct ntp_unit unit;
	GDir *dir;
	guint i, j;

	free_ntp_units();

	g_assert(!ntp_units);
	ntp_units = g_array_new(FALSE, FALSE, sizeof (struct ntp_unit));

	/* Read the NTP unit names from files in ntp-unit.d directories */

	unit_dirs = g_strsplit(NTP_UNITS_PATHS, ":", -1);

	for (unit_dir = unit_dirs; *unit_dir; unit_dir++) {
		dir = g_dir_open(*unit_dir, 0, NULL);
		if (!dir)
			continue;

		while ((entry = g_dir_read_name(dir))) {
			snprintf(path, sizeof path, "%s/%s", *unit_dir, entry);
			if (!g_file_get_contents(path, &contents, NULL, NULL))
				continue;
			lines = g_strsplit_set(contents, "\r\n", -1);
			g_free(contents);

			for (line = lines; *line; line++) {
				if (!**line || **line == '#')
					continue;

				/* Ignore units that can't be loaded */
				if (!call_systemd_noresult("LoadUnit", g_variant_new("(s)", *line)))
					continue;

				unit.name = g_strdup(*line);
				unit.sort_name = g_strdup(entry);
				g_array_append_val(ntp_units, unit);
			}
			g_strfreev(lines);
		}

		g_dir_close(dir);
	}

	g_strfreev(unit_dirs);

	/* Sort the units by filename */
	g_array_sort(ntp_units, compare_ntp_units);

	/* Remove duplicates, keep only the first entry for each unit */
	for (i = 0; i < ntp_units->len; i++) {
		for (j = i + 1; j < ntp_units->len; ) {
			if (g_strcmp0(get_ntp_unit(i)->name, get_ntp_unit(j)->name)) {
				j++;
				continue;
			}
			g_free(get_ntp_unit(j)->name);
			g_free(get_ntp_unit(j)->sort_name);
			g_array_remove_index(ntp_units, j);
		}
	}
}

static void update_ntp_units(void) {
	free_ntp_units();
	read_ntp_units();
}

static GVariant *get_ntp_available(void) {
	return g_variant_new_boolean(ntp_units->len ? TRUE : FALSE);
}

static gboolean is_ntp_active(void) {
	gchar *unit_path;
	GVariant *result;
	GVariant *state;
	gboolean ret;

	if (!ntp_units->len)
		return FALSE;

	result = call_systemd("LoadUnit", g_variant_new("(s)", get_ntp_unit(0)->name));
	if (!result)
		return FALSE;

	g_variant_get(result, "(&o)", &unit_path);

	state = get_object_property(SYSTEMD_NAME, unit_path, SYSTEMD_UNIT_INTERFACE, "ActiveState");
	g_variant_unref(result);
	if (!state)
		return FALSE;

	ret = g_strcmp0(g_variant_get_string(state, NULL), "active") == 0 ||
		g_strcmp0(g_variant_get_string(state, NULL), "activating") == 0;
	g_variant_unref(state);

	return ret;
}

static GVariant *get_ntp_active(void) {
	return g_variant_new_boolean(is_ntp_active());
}

static void finish_set_ntp_active(GDBusMethodInvocation *invocation, struct method_call_data *data) {
	GVariantBuilder builder1, builder2;
	gchar *unit_name;
	guint i, enable, disable;

	/* Reload the list to get new NTP units installed on the system */
	update_ntp_units();

	/* Start and enable the first NTP unit if active is true. Stop and disable
	   everything else. Errors are ignored for other units than first. */

	for (i = enable = disable = 0; i < ntp_units->len; i++) {
		unit_name = get_ntp_unit(i)->name;

		if (!i && data->set_ntp_active.active) {
			if (!call_systemd_noresult("StartUnit", g_variant_new("(ss)", unit_name, "replace")))
			       if (!i)
				       goto error;
			if (!enable++)
				g_variant_builder_init(&builder1, G_VARIANT_TYPE("as"));
			g_variant_builder_add(&builder1, "s", unit_name);
		} else {
			if (!call_systemd_noresult("StopUnit", g_variant_new("(ss)", unit_name, "replace")))
				if (!i)
					goto error;
			if (!disable++)
				g_variant_builder_init(&builder2, G_VARIANT_TYPE("as"));
			g_variant_builder_add(&builder2, "s", unit_name);
		}
	}

	if (enable)
		call_systemd_noresult("EnableUnitFiles", g_variant_new("(asbb)", &builder1, FALSE, TRUE));
	if (disable)
		call_systemd_noresult("DisableUnitFiles", g_variant_new("(asb)", &builder2, FALSE));

	/* This seems to be needed to update the unit state reported by systemd */
	if (enable || disable)
		call_systemd_noresult("Reload", g_variant_new("()"));

	emit_property_change(g_dbus_method_invocation_get_connection(invocation),
			     "NTP", g_variant_new_boolean(data->set_ntp_active.active));
	return_success(invocation);
	return;
error:
	return_error(invocation, G_DBUS_ERROR_FAILED, "Failed to start/stop NTP unit");
}

static void set_ntp_active(GVariant *parameters, GDBusMethodInvocation *invocation, const gchar *caller) {
	gboolean user_interaction;
	struct method_call_data data;

	g_variant_get(parameters, "(bb)", &data.set_ntp_active.active, &user_interaction);

	if (!ntp_units->len) {
		return_error(invocation, G_DBUS_ERROR_FAILED, "No NTP unit available");
		return;
	}

	if (data.set_ntp_active.active == is_ntp_active()) {
		return_success(invocation);
		return;
	}

	start_auth_check(caller, POLKIT_ACTION_SET_NTP_ACTIVE, user_interaction, invocation,
			 finish_set_ntp_active, &data);
}

static GVariant *get_clock_synchronized(void) {
	struct timex t;
	gboolean ret;

	/* Consider the system clock synchronized if the maximum error reported
	   by adjtimex() is smaller than 10 seconds. Ignore the STA_UNSYNC flag
	   as it may be set to prevent the kernel from touching the RTC. */
	t.modes = 0;
	ret = adjtimex(&t) >= 0 && t.maxerror < 10000000;

	return g_variant_new_boolean(ret);
}

static GVariant *get_system_time(void) {
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return g_variant_new_uint64((guint64)tv.tv_sec * 1000000 + tv.tv_usec);
}

static void finish_set_time(GDBusMethodInvocation *invocation, struct method_call_data *data) {
	struct timeval tv;
	struct timex tx;

	if (data->set_time.relative) {
		tx.modes = ADJ_SETOFFSET | ADJ_NANO;

		tx.time.tv_sec = data->set_time.requested_time / 1000000;
		tx.time.tv_usec = data->set_time.requested_time - tx.time.tv_sec * 1000000;
		if (tx.time.tv_usec < 0) {
			tx.time.tv_sec--;
			tx.time.tv_usec += 1000000;
		}

		/* Convert to nanoseconds */
		tx.time.tv_usec *= 1000;

		if (adjtimex(&tx) < 0)
			goto error;
	} else {
		/* Compensate for the time taken by the authorization check */
		data->set_time.requested_time += g_get_monotonic_time() - data->set_time.request_time;

		tv.tv_sec = data->set_time.requested_time / 1000000;
		tv.tv_usec = data->set_time.requested_time - tv.tv_sec * 1000000;
		if (settimeofday(&tv, NULL))
			goto error;
	}

	return_success(invocation);

	/* Set the RTC to the new system time */
	start_hwclock_call(FALSE, FALSE, FALSE, NULL, NULL, NULL);

	return;
error:
	return_error(invocation, G_DBUS_ERROR_FAILED, "Failed to set system clock: %s", strerror(errno));
}

static void set_time(GVariant *parameters, GDBusMethodInvocation *invocation, const gchar *caller) {
	gboolean user_interaction;
	struct method_call_data data;
	GVariant *variant;
	gboolean ntp_active;

	data.set_time.request_time = g_get_monotonic_time();
	g_variant_get(parameters, "(xbb)", &data.set_time.requested_time, &data.set_time.relative,
		      &user_interaction);

	variant = get_ntp_active();
	ntp_active = g_variant_get_boolean(variant);
	g_variant_unref(variant);

	if (ntp_active) {
		return_error(invocation, G_DBUS_ERROR_FAILED, "NTP unit is active");
		return;
	}

	start_auth_check(caller, POLKIT_ACTION_SET_TIME, user_interaction, invocation,
			 finish_set_time, &data);
}

static GVariant *get_rtc_time(void) {
	struct rtc_time rtc;
	struct tm tm;
	time_t rtc_time = 0;
	int fd, r;

	fd = open(RTC_DEVICE, O_RDONLY);
	if (fd < 0)
		goto error;

	r = ioctl(fd, RTC_RD_TIME, &rtc);
	close(fd);
	if (r)
		goto error;

	tm.tm_sec = rtc.tm_sec;
	tm.tm_min = rtc.tm_min;
	tm.tm_hour = rtc.tm_hour;
	tm.tm_mday = rtc.tm_mday;
	tm.tm_mon = rtc.tm_mon;
	tm.tm_year = rtc.tm_year;
	tm.tm_isdst = 0;

	/* This is the raw time as if the RTC was in UTC */
	rtc_time = timegm(&tm);

error:
	return g_variant_new_uint64((guint64)rtc_time * 1000000);
}

static gboolean is_rtc_local(void) {
	gboolean ret;
	gchar *contents;

	if (!g_file_get_contents(ADJTIME_PATH, &contents, NULL, NULL))
		return FALSE;

	ret = !!strstr(contents, "LOCAL");
	g_free(contents);

	return ret;
}

static GVariant *get_rtc_local(void) {
	return g_variant_new_boolean(is_rtc_local());
}

static void finish_set_rtc_local_hwclock(GDBusMethodInvocation *invocation, struct method_call_data *data) {
	emit_property_change(g_dbus_method_invocation_get_connection(invocation),
			     "LocalRTC", g_variant_new_boolean(data->set_rtc_local.local));
	return_success(invocation);
}

static void finish_set_rtc_local(GDBusMethodInvocation *invocation, struct method_call_data *data) {
	start_hwclock_call(data->set_rtc_local.adjust_system, data->set_rtc_local.local,
			   !data->set_rtc_local.local, invocation, finish_set_rtc_local_hwclock, data);
}

static void set_rtc_local(GVariant *parameters, GDBusMethodInvocation *invocation, const gchar *caller) {
	gboolean user_interaction;
	struct method_call_data data;

	g_variant_get(parameters, "(bbb)", &data.set_rtc_local.local, &data.set_rtc_local.adjust_system,
		      &user_interaction);

	if (data.set_rtc_local.local == is_rtc_local()) {
		return_success(invocation);
		return;
	}

	start_auth_check(caller, POLKIT_ACTION_SET_RTC_LOCAL, user_interaction, invocation,
			 finish_set_rtc_local, &data);
}

static GVariant *get_timezone(void) {
	gchar *link, *zone;
	GVariant *ret;

	link = g_file_read_link(LOCALTIME_PATH, NULL);
	if (!link)
		goto error;

	zone = g_strrstr(link, ZONEINFO_PATH);
	if (!zone)
		goto error;

	zone += strlen(ZONEINFO_PATH);

	ret = g_variant_new_string(zone);
	g_free(link);

	return ret;
error:
	/* Empty string means N/A */
	return g_variant_new_string("");
}

static void set_localtime_file_context(const gchar *path) {
#ifdef HAVE_SELINUX
	security_context_t con;

	if (!is_selinux_enabled())
		return;

	if (matchpathcon_init_prefix(NULL, LOCALTIME_PATH))
		return;

	if (!matchpathcon(LOCALTIME_PATH, S_IFLNK, &con)) {
		lsetfilecon(path, con);
		freecon(con);
	}

	matchpathcon_fini();
#endif
}

static void update_kernel_utc_offset(void) {
	struct timezone tz;
	struct timeval tv;
	struct tm *tm;

	if (gettimeofday(&tv, &tz))
		goto error;

	tm = localtime(&tv.tv_sec);
	if (!tm)
		goto error;

	/* tm_gmtoff is in seconds east of UTC */
	tz.tz_minuteswest = -tm->tm_gmtoff / 60;

	if (settimeofday(NULL, &tz))
		goto error;

	return;
error:
	g_printerr("Failed to update kernel UTC offset\n");
}

static gboolean check_timezone_name(const gchar *name) {
	gint i;
	gchar link[PATH_MAX];
	struct stat st;

	/* Check if the name is sane */
	if (!name || *name == '/' || strstr(name, "//") || strstr(name, "..") ||
	    strlen(name) > MAX_TIMEZONE_LENGTH)
		return FALSE;

	for (i = 0; name[i]; i++) {
		if (!g_ascii_isalnum(name[i]) && !strchr("+-_/", name[i]))
			return FALSE;
	}

	/* Check if the correspoding file exists in the zoneinfo directory, it
	   doesn't have to be listed in zone.tab */
	if (snprintf(link, sizeof link, "%s%s", ZONEINFO_PATH, name) >= sizeof link)
		return FALSE;
	if (stat(link, &st) || !(st.st_mode & S_IFREG))
		return FALSE;

	return TRUE;
}

static void finish_set_timezone(GDBusMethodInvocation *invocation, struct method_call_data *data) {
	gchar link[PATH_MAX], tmp[PATH_MAX];

	if (snprintf(link, sizeof link, "%s%s%s", LOCALTIME_TO_ZONEINFO_PATH, ZONEINFO_PATH,
		     data->set_timezone.timezone) >= sizeof link)
		goto error;

	if (snprintf(tmp, sizeof tmp, "%s.%06u", LOCALTIME_PATH, g_random_int()) >= sizeof tmp)
		goto error;

	if (symlink(link, tmp))
		goto error;

	set_localtime_file_context(tmp);

	if (rename(tmp, LOCALTIME_PATH)) {
		unlink(tmp);
		goto error;
	}

	emit_property_change(g_dbus_method_invocation_get_connection(invocation),
			     "Timezone", g_variant_new_string(data->set_timezone.timezone));
	return_success(invocation);

	update_kernel_utc_offset();

	/* RTC in local needs to be set for the new timezone */
	if (is_rtc_local())
		start_hwclock_call(FALSE, FALSE, FALSE, NULL, NULL, NULL);

	return;
error:
	return_error(invocation, G_DBUS_ERROR_FAILED, "Failed to update %s", LOCALTIME_PATH);
}

static void set_timezone(GVariant *parameters, GDBusMethodInvocation *invocation,
			 const gchar *caller) {
	gboolean user_interaction, no_change;
	const gchar *timezone;
	struct method_call_data data;
	GVariant *current_timezone;

	g_variant_get(parameters, "(&sb)", &timezone, &user_interaction);

	if (!check_timezone_name(timezone)) {
		return_error(invocation, G_DBUS_ERROR_INVALID_ARGS, "Invalid timezone");
		return;
	}

	current_timezone = get_timezone();
	no_change = !g_strcmp0(g_variant_get_string(current_timezone, NULL), timezone);
	g_variant_unref(current_timezone);

	if (no_change) {
		return_success(invocation);
		return;
	}

	snprintf(data.set_timezone.timezone, sizeof data.set_timezone.timezone, "%s", timezone);

	start_auth_check(caller, POLKIT_ACTION_SET_TIMEZONE, user_interaction, invocation,
			 finish_set_timezone, &data);
}

static void handle_method_call(GDBusConnection *connection, const gchar *caller, const gchar *object_path,
			       const gchar *interface_name, const gchar *method_name, GVariant *parameters,
			       GDBusMethodInvocation *invocation, gpointer user_data) {
	GVariantBuilder builder;
	GVariant *result;
	const gchar *interface, *property;

	if (!g_strcmp0(interface_name, TIMEDATED_INTERFACE)) {
		if (!g_strcmp0(method_name, "SetTime"))
			set_time(parameters, invocation, caller);
		else if (!g_strcmp0(method_name, "SetTimezone"))
			set_timezone(parameters, invocation, caller);
		else if (!g_strcmp0(method_name, "SetLocalRTC"))
			set_rtc_local(parameters, invocation, caller);
		else if (!g_strcmp0(method_name, "SetNTP"))
			set_ntp_active(parameters, invocation, caller);
		else
			g_assert_not_reached();

	} else if (!g_strcmp0(interface_name, PROPERTIES_INTERFACE)) {
		if (!g_strcmp0(method_name, "Get")) {

			g_variant_get(parameters, "(&s&s)", &interface, &property);

			if (g_strcmp0(interface, TIMEDATED_INTERFACE) && g_strcmp0(interface, "")) {
				return_error(invocation, G_DBUS_ERROR_INVALID_ARGS, "No such interface");
				return;
			}

			if (!g_strcmp0(property, "Timezone"))
				result = get_timezone();
			else if (!g_strcmp0(property, "LocalRTC"))
				result = get_rtc_local();
			else if (!g_strcmp0(property, "CanNTP"))
				result = get_ntp_available();
			else if (!g_strcmp0(property, "NTP"))
				result = get_ntp_active();
			else if (!g_strcmp0(property, "NTPSynchronized"))
				result = get_clock_synchronized();
			else if (!g_strcmp0(property, "TimeUSec"))
				result = get_system_time();
			else if (!g_strcmp0(property, "RTCTimeUSec"))
				result = get_rtc_time();
			else {
				return_error(invocation, G_DBUS_ERROR_INVALID_ARGS, "No such property");
				return;
			}

			g_dbus_method_invocation_return_value(invocation, g_variant_new("(v)", result));

		} else if (!g_strcmp0(method_name, "GetAll")) {
			g_variant_get(parameters, "(&s)", &interface);

			if (g_strcmp0(interface, TIMEDATED_INTERFACE) && g_strcmp0(interface, "")) {
				return_error(invocation, G_DBUS_ERROR_INVALID_ARGS, "No such interface");
				return;
			}

			g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
			g_variant_builder_add(&builder, "{sv}", "Timezone", get_timezone());
			g_variant_builder_add(&builder, "{sv}", "LocalRTC", get_rtc_local());
			g_variant_builder_add(&builder, "{sv}", "CanNTP", get_ntp_available());
			g_variant_builder_add(&builder, "{sv}", "NTP", get_ntp_active());
			g_variant_builder_add(&builder, "{sv}", "NTPSynchronized", get_clock_synchronized());
			g_variant_builder_add(&builder, "{sv}", "TimeUSec", get_system_time());
			g_variant_builder_add(&builder, "{sv}", "RTCTimeUSec", get_rtc_time());

			result = g_variant_new("(a{sv})", &builder);

			g_dbus_method_invocation_return_value(invocation, result);

		} else if (!g_strcmp0(method_name, "Set")) {
			g_variant_get(parameters, "(&s&sv)", &interface, &property, NULL);
			return_error(invocation, G_DBUS_ERROR_INVALID_ARGS, "Property %s not writable",
				     property);
		} else {
			g_assert_not_reached();
		}
	} else {
		g_assert_not_reached();
	}
}

static const GDBusInterfaceVTable interface_vtable = {
	.method_call = handle_method_call,
	.get_property = NULL,
};

static void register_object(GDBusConnection *connection, const gchar *name, gpointer user_data) {
	GDBusNodeInfo *bus_node_info;
	GDBusInterfaceInfo *timedated_interface, *properties_interface;
	GError *error;

	error = NULL;
	bus_node_info = g_dbus_node_info_new_for_xml(TIMEDATED_XML, &error);
	if (!bus_node_info)
		goto error;

	timedated_interface = bus_node_info->interfaces[3];
	properties_interface = bus_node_info->interfaces[2];

	g_assert(!g_strcmp0(timedated_interface->name, TIMEDATED_INTERFACE));
	g_assert(!g_strcmp0(properties_interface->name, PROPERTIES_INTERFACE));

	error = NULL;
	if (!g_dbus_connection_register_object(connection, TIMEDATED_PATH, timedated_interface,
					       &interface_vtable, NULL, NULL, &error))
		goto error;

	/* We need to handle the properties interface ourself as gdbus doesn't
	   support GetAll calls with empty interface name (e.g. from timedatectl),
	   https://bugzilla.gnome.org/show_bug.cgi?id=741101 */
	error = NULL;
	if (!g_dbus_connection_register_object(connection, TIMEDATED_PATH, properties_interface,
					       &interface_vtable, NULL, NULL, &error))
		goto error;

	g_dbus_node_info_unref(bus_node_info);
	return;
error:
	g_printerr("Failed to register dbus object: %s\n", error->message);
	g_error_free(error);
	g_assert_not_reached();
}

static gboolean stop_main_loop(gpointer user_data) {
	main_quit = TRUE;

	/* Keep the timeout, it will be removed in the main loop */
	return TRUE;
}

int main(int argc, char **argv) {
	guint owner_id = 0, timeout_id = 0;
	int ret = 1;

	if (argc > 1) {
		g_printerr("No options supported\n");
		return 1;
	}

	systemd_proxy = get_bus_proxy(SYSTEMD_NAME, SYSTEMD_PATH, SYSTEMD_MANAGER_INTERFACE);
	if (!systemd_proxy)
		goto error;

	polkit_proxy = get_bus_proxy(POLKIT_NAME, POLKIT_PATH, POLKIT_INTERFACE);
	if (!polkit_proxy)
		goto error;

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, TIMEDATED_NAME, G_BUS_NAME_OWNER_FLAGS_REPLACE,
				  register_object, NULL, NULL, NULL, NULL);

	read_ntp_units();

	main_quit = FALSE;

	/* This is the main loop. Quit when idle for QUIT_TIMEOUT seconds. */

	while (!main_quit) {
		/* Add timeout when not waiting for an authorization check */
		if (!running_auth_checks)
			timeout_id = g_timeout_add(QUIT_TIMEOUT * 1000, stop_main_loop, NULL);

		g_main_context_iteration(g_main_context_default(), TRUE);

		if (timeout_id)
			g_source_remove(timeout_id);
		timeout_id = 0;
	}

	ret = 0;

error:
	if (owner_id)
		g_bus_unown_name(owner_id);
	if (polkit_proxy)
		g_object_unref(polkit_proxy);
	if (systemd_proxy)
		g_object_unref(systemd_proxy);

	free_ntp_units();

	return ret;
}
