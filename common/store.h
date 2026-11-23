/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * store.h - /var/db/bluetoothmgr/devices.json. SPEC.md A4.
 *
 * The one file in Part A that is ours alone, which changes what the A0 rules
 * ask for. A0.4 exists to protect content someone else wrote; here there is
 * none, so emission is a full rewrite from the model and a field we do not
 * recognise is dropped rather than preserved. A0.1, A0.2 and A0.5 still apply,
 * and come from safefile_write() as usual.
 *
 * A4.1: no PINs and no link keys, ever. Those belong to hcsecd.conf and
 * hcsecd.keys. There is no setter here that could accept one, and a "pin" or
 * "key" field found in the file on disk is dropped on the next write rather
 * than carried forward.
 *
 * A4.3: a file that does not parse loads as an empty store, and the next write
 * replaces it.
 *
 * Times are seconds since the epoch, as int64_t rather than time_t so the
 * on-disk format does not change shape with the platform. 0 means never.
 */

#ifndef BTMGR_STORE_H_
#define	BTMGR_STORE_H_

#include <stddef.h>
#include <stdint.h>

#include "btaddr.h"

/* A4.2. Bumped when the on-disk shape changes incompatibly. */
#define	STORE_VERSION		1

struct store;

enum store_result {
	STORE_ERROR	= -1,
	STORE_CHANGED	= 0,
	STORE_UNCHANGED	= 1,	/* already says this */
	STORE_ABSENT	= 2	/* no such device */
};

/* An empty store, for a first run. */
struct store	*store_new(void);

/*
 * Parse. A NULL or empty text gives an empty store and is not a failure.
 *
 * When the top level is unusable, meaning not an object, or without an integer
 * version, or a version newer than STORE_VERSION, or with a devices field that
 * is not an array, the result is an empty store and *malformed is set.
 *
 * An individual entry that is unusable is skipped and counted in *skipped.
 *
 * malformed and skipped may be NULL. Returns NULL only on allocation failure.
 */
struct store	*store_parse(const char *text, int *malformed,
		     size_t *skipped);
void		 store_free(struct store *st);

/*
 * Render. Keys are sorted and devices keep insertion order, so the same model
 * always produces the same bytes, which is what makes A0.5 work. Ends in '\n'.
 * Caller frees.
 */
char		*store_emit(const struct store *st, size_t *lenp);

int		 store_dirty(const struct store *st);
size_t		 store_count(const struct store *st);

int		 store_has(const struct store *st, const uint8_t *addr);

/* All NULL or 0 when there is no such device. Strings die with the model. */
const char	*store_name(const struct store *st, const uint8_t *addr);
const char	*store_alias(const struct store *st, const uint8_t *addr);
const char	*store_type(const struct store *st, const uint8_t *addr);
int64_t		 store_first_seen(const struct store *st, const uint8_t *addr);
int64_t		 store_last_connected(const struct store *st,
		     const uint8_t *addr);
int		 store_auto_connect(const struct store *st,
		     const uint8_t *addr);

size_t		 store_addrs(const struct store *st,
		     uint8_t (*out)[BTMGR_ADDR_LEN], size_t max);

/*
 * Add or update the metadata for addr. name, alias and type may be NULL to
 * leave that field alone on an existing device. first_seen is set to now only
 * when the device is new; now is ignored otherwise.
 *
 * type is the B5.3 vocabulary as a string, which is what goes on the wire, and
 * keeps this module clear of the HCI headers.
 */
enum store_result store_set(struct store *st, const uint8_t *addr,
		     const char *name, const char *alias, const char *type,
		     int64_t now);

enum store_result store_touch_connected(struct store *st, const uint8_t *addr,
		     int64_t when);
enum store_result store_set_auto_connect(struct store *st,
		     const uint8_t *addr, int on);
enum store_result store_remove(struct store *st, const uint8_t *addr);

#endif /* !BTMGR_STORE_H_ */
