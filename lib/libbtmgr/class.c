/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * class.c - decode the Bluetooth "class of device" into our type vocabulary.
 *
 * Class of device is 24 bits packed as:
 *
 *   bits 23..13   service classes (bitfield: audio, rendering, telephony, ...)
 *   bits 12..8    major device class
 *   bits  7..2    minor device class, interpreted per major class
 *   bits  1..0    format type, always 00 for the format we handle
 *
 * The three bytes arrive little endian, so devclass[0] is the low byte.
 * Worked example from a real inquiry, "Basement TV 2" reporting 28:04:3c:
 *
 *   value = 0x28043c
 *   major = (0x28043c >> 8) & 0x1f = 0x04   Audio/Video
 *   minor = (0x28043c >> 2) & 0x3f = 0x0f   Video Display and Loudspeaker
 */

#include "btmgr.h"

/* Major device classes we care about. */
#define	MAJOR_COMPUTER		0x01
#define	MAJOR_PHONE		0x02
#define	MAJOR_AV		0x04
#define	MAJOR_PERIPHERAL	0x05

/* Minor classes under MAJOR_AV. */
#define	AV_HEADSET		0x01
#define	AV_HANDSFREE		0x02
#define	AV_MICROPHONE		0x04
#define	AV_LOUDSPEAKER		0x05
#define	AV_HEADPHONES		0x06
#define	AV_PORTABLE_AUDIO	0x07
#define	AV_CAR_AUDIO		0x08
#define	AV_HIFI			0x0a

/*
 * Under MAJOR_PERIPHERAL the minor class is itself split: the top two bits
 * flag keyboard and pointing device, the low four are the device kind.
 */
#define	PERIPH_KBD_MASK		0x30
#define	PERIPH_KBD		0x10
#define	PERIPH_POINTING		0x20

/*
 * Decode a class of device.
 *
 * Takes the raw three bytes as they come off the wire. Returns
 * BTMGR_TYPE_UNKNOWN rather than failing, because a device is free to report
 * anything and an unrecognised class is not an error.
 */
enum btmgr_type
btmgr_class_type(const uint8_t *devclass)
{
	uint32_t	value, major, minor;

	if (devclass == NULL)
		return (BTMGR_TYPE_UNKNOWN);

	/* Reassemble the little endian bytes into one 24 bit value. */
	value = ((uint32_t)devclass[2] << 16) |
		((uint32_t)devclass[1] << 8) |
		 (uint32_t)devclass[0];

	major = (value >> 8) & 0x1f;
	minor = (value >> 2) & 0x3f;

	switch (major) {
	case MAJOR_COMPUTER:
		return (BTMGR_TYPE_COMPUTER);

	case MAJOR_PHONE:
		return (BTMGR_TYPE_PHONE);

	case MAJOR_AV:
		switch (minor) {
		case AV_HEADSET:
		case AV_HANDSFREE:
			return (BTMGR_TYPE_HEADSET);
		case AV_HEADPHONES:
			return (BTMGR_TYPE_HEADPHONES);
		case AV_LOUDSPEAKER:
		case AV_PORTABLE_AUDIO:
		case AV_CAR_AUDIO:
		case AV_HIFI:
			return (BTMGR_TYPE_SPEAKER);
		default:
			return (BTMGR_TYPE_AV);
		}

	case MAJOR_PERIPHERAL:
		/*
		 * A combo keyboard/pointing device reports both bits. Call it
		 * a keyboard, since that is the half that matters to bthidd.
		 */
		if ((minor & PERIPH_KBD_MASK) == PERIPH_POINTING)
			return (BTMGR_TYPE_MOUSE);
		if (minor & PERIPH_KBD)
			return (BTMGR_TYPE_KEYBOARD);
		return (BTMGR_TYPE_UNKNOWN);

	default:
		return (BTMGR_TYPE_UNKNOWN);
	}
}

/*
 * Stable short names, matching the vocabulary in SPEC.md B5.3. These go on
 * the wire, so they must not change casually.
 */
const char *
btmgr_type_name(enum btmgr_type type)
{
	switch (type) {
	case BTMGR_TYPE_COMPUTER:	return ("computer");
	case BTMGR_TYPE_PHONE:		return ("phone");
	case BTMGR_TYPE_HEADSET:	return ("headset");
	case BTMGR_TYPE_HEADPHONES:	return ("headphones");
	case BTMGR_TYPE_SPEAKER:	return ("speaker");
	case BTMGR_TYPE_AV:		return ("av");
	case BTMGR_TYPE_KEYBOARD:	return ("keyboard");
	case BTMGR_TYPE_MOUSE:		return ("mouse");
	case BTMGR_TYPE_UNKNOWN:	return ("unknown");
	}

	/*
	 * Unreachable if the enum is handled exhaustively above, which the
	 * compiler checks for us with -Wswitch. Kept so the function has a
	 * return on every path.
	 */
	return ("unknown");
}