# BluetoothMgr — Implementation Plan

Status: M1, M2 done and M3a written. `lib/libbtmgr`, `tools/btmgr-probe` and
`bluetoothmgrd` build and run, verified on hardware. M3a, the privileged
operations, is next. Section 6 tracks progress per milestone.

See `SPEC.md` for the normative contract. This document holds the research
and the reasoning; the spec holds the rules.

This document supersedes the architecture guesses in the original project brief
wherever the two disagree. Every claim below marked **[verified]** was checked
against the source tree in `../ghostbsd-src` or executed on this machine
(GhostBSD 26.1, FreeBSD 15.0-RELEASE-p13, amd64) on 2026-09-22.

---

## 0. How to read this document

Sections 1 to 3 are the research result: what FreeBSD actually gives us. Read
them first, because several of the findings invalidate assumptions that look
reasonable from the outside. F7 and F8 in particular were only found by
reading the base system's source and then hitting them in practice.

Section 4 is the revised architecture. Section 5 is a C learning track, since
this project is also the vehicle for getting comfortable in C. Sections 6 to 8
are the build order, the resolved decisions, and the risks.

---

## 1. Ground truth: measured on this machine

I compiled and ran three small probe programs against the live stack, all as an
ordinary user. Results:

| Fact | Value | How |
|---|---|---|
| Kernel modules loaded | `ng_ubt`, `ng_hci`, `ng_bluetooth`, `ng_l2cap`, `ng_btsocket`, `ng_socket` | `kldstat` |
| Adapter | CSR dongle at `ugen0.2`, node `ubt0hci` | `usbconfig`, `bt_devenum()` |
| Adapter BD_ADDR | `00:1a:7d:da:71:13` | `bt_devinfo()` |
| Adapter state | `0x00000003`, inited | `bt_devinfo()` |
| Adapter friendly name | `ericbsd-ghostbsd-pc (ubt0)` | `HCI_Read_Local_Name` |
| Scan enable | `0x03`, inquiry scan ON, page scan ON | `HCI_Read_Scan_Enable` |
| Class of device | `ff:01:0c` | `HCI_Read_Unit_Class` |
| Running daemons | `hcsecd`, `sdpd`. Not `bthidd` | `pgrep` |
| Stack brought up by | `devd`, automatically on USB attach | `/etc/devd/bluetooth.conf` |
| Inquiry as normal user | works, found `bc:5c:17:c6:87:3f` "Basement TV 2" class `28:04:3c` | probe2 |
| Existing alias | `0f:44:53:d2:d7:88  headphones` | `/etc/bluetooth/hosts` |

Toolchain and libraries, all present: clang 19.1.7, `gtk+-3.0`,
`libmatepanelapplet-4.0`, `glib-2.0`, `json-glib-1.0`, `jansson`, `libbluetooth`,
`libsdp`, `virtual_oss`, `pactl`.

The probe sources are committed as `tools/probe/` so the datapoint is
reproducible on other hardware. `tools/btmgr-probe` supersedes them for day to
day use; the three originals are kept as the record of what was measured when.

---

## 2. The mental model: FreeBSD Bluetooth is not BlueZ

On Linux, BlueZ is one privileged daemon that owns the adapter and exposes
everything over D-Bus. Applications never touch HCI. On FreeBSD the same
responsibilities are scattered, and there is no central object model at all.

```
   USB dongle (ugen0.2)
        |
   ng_ubt        <- USB transport driver, netgraph node "ubt0"
        |
   ng_hci        <- HCI layer, node "ubt0hci". Tracks connections,
        |            neighbour cache, unit state.
        +----------------------------+
        |                            |
   ng_l2cap                   btsock_hci_raw
   node "ubt0l2cap"                  |
        |                     AF_BLUETOOTH/SOCK_RAW/BLUETOOTH_PROTO_HCI
   btsock_l2cap                      |
        |                    +-------+--------+-------------------+
   L2CAP sockets             |                |                   |
        |                  hcsecd          hccontrol        bluetoothmgrd
   sdpd, bthidd,          (pairing)        (CLI tool)         (us, new)
   btpand, virtual_oss
```

The pieces and who owns what today:

- **`ng_hci`** keeps the authoritative connection list in the kernel. We read it
  with one ioctl, no HCI round trip needed.
- **`hcsecd`** is the pairing agent. It listens for three HCI events and answers
  them from `/etc/bluetooth/hcsecd.conf` and `/var/db/hcsecd.keys`.
- **`sdpd`** is the local service registry, so remote devices can discover what
  *we* offer. Querying what a *remote* device offers is a separate client-side
  L2CAP conversation via `libsdp`.
- **`bthidd`** connects paired HID devices and feeds them into the console.
- **`/etc/bluetooth/hosts`** is a flat address to alias file, read by
  `bt_gethostbyname()` and `bt_gethostbyaddr()`, which is what `bthost(1)` uses.
  It is `/etc/hosts` for Bluetooth. Note that `bt_devname()` and `bt_devaddr()`
  sound related but are not: they map between *local adapters* and their
  addresses, and never touch this file.
- **`virtual_oss`** handles A2DP audio entirely outside this picture, by opening
  its own L2CAP socket through its `voss_bt.so` plugin.

There is no event bus, no device database, and no concept of an adapter being
"powered off". That absence is the gap BluetoothMgr fills.

---

## 3. Findings that change the design

### F1. `libbluetooth` already wraps the raw HCI socket. Use it. **[verified]**

The brief says the daemon should talk raw `AF_BLUETOOTH` sockets directly. That
work is already done in `/usr/lib/libbluetooth.so`, source at
`../ghostbsd-src/lib/libbluetooth/hci.c`. It gives us:

| Function | What it does |
|---|---|
| `bt_devopen("ubt0hci")` | socket + bind + connect, returns an fd |
| `bt_devenum(cb, arg)` | enumerate all HCI nodes, calls `cb` per node |
| `bt_devinfo(&di)` | 9 ioctls worth of adapter state in one call |
| `bt_devreq(s, &r, to)` | send an HCI command, wait for its completion event |
| `bt_devinquiry(...)` | full scan, returns an array of results |
| `bt_devremote_name(...)` | resolve a remote device's friendly name |
| `bt_devfilter*` | control which events this socket receives |
| `bt_ntoa` / `bt_aton` | BD_ADDR to string and back |
| `bt_devname` / `bt_devaddr` | map a *local adapter* between node name and address |

`bt_devreq()` in particular is worth reading. It handles the correlation problem
for us: it temporarily narrows the socket filter, sends the command, then loops
reading events until it sees a `Command_Complete` or `Command_Status` whose
opcode matches what it sent, and restores the old filter on the way out.

**Decision:** link `-lbluetooth`. We write raw socket code only for the one thing
the library does not cover, which is the long-lived passive event listener
(section F3).

One practical gotcha: `#include <bluetooth.h>` emits a `#warning` unless you
`#define L2CAP_SOCKET_CHECKED` first. libbluetooth's own sources do exactly
that. Do the same in our headers.

### F2. The root boundary is exactly "reads versus writes". **[verified]**

`ng_btsocket_hci_raw.c` sets a `PRIVILEGED` flag on the socket at creation time
based on `priv_check(td, PRIV_NETBLUETOOTH_RAW)`. Unprivileged sockets are then
checked against a static allowlist, `ng_btsocket_hci_raw_sec_filter`, built at
module init around line 810.

Measured as user `ericbsd`, no sudo:

```
bt_devopen("ubt0hci")              ok
bt_devenum / bt_devinfo            ok
SIOC_HCI_RAW_NODE_GET_CON_LIST     ok, returned 0 connections
HCI_Read_Local_Name                ok
HCI_Read_Scan_Enable               ok
HCI_Read_Unit_Class                ok
bt_devinquiry (full scan)          ok, found a device
bt_devremote_name                  ok, resolved its name
SIOC_HCI_RAW_NODE_SET_DEBUG        EPERM   <-- the boundary
```

The allowlist covers every `Read_*` command, plus `Inquiry`,
`Inquiry_Cancel`, `Periodic_Inquiry`, `Remote_Name_Request`,
`Read_Remote_Features`, `Role_Discovery`, and the LE scan commands. Every
`Write_*`, `Create_Connection`, `Disconnect`, and every `SET` ioctl needs root.

Also note: the sec filter *clears* three events for unprivileged sockets, namely
`Return_Link_Keys`, `Link_Key_Notification`, and `Vendor`. So link key material
is not readable without root, which is correct.

**Why this matters.** The brief assumed one root daemon doing everything. In
fact all of scanning, device listing, name resolution, and connection state is
available to an ordinary user process. That means:

- The daemon runs as root only because it needs `connect`, `disconnect`,
  `Write_Scan_Enable`, and config file writes.
- Everything it does *in the polling loop* needs no privilege at all.
- A future hardening step could split it, with a small root helper and an
  unprivileged poller. We do not need that in v1, but the design should not
  block it.

### F3. HCI events are broadcast, so `hcsecd` is a co-tenant. **[verified]**

`ng_btsocket_hci_raw_data_input()` walks the socket list with `LIST_FOREACH` and
delivers a `m_dup()` copy of every incoming packet to *every* socket whose bind
address and filter match. It is a broadcast, not a handoff.

Consequences, both directions:

- **Good:** `bluetoothmgrd` can passively watch the exact same events `hcsecd`
  sees, including `Connection_Complete`, `Disconnection_Complete`,
  `PIN_Code_Request` and `Authentication_Complete`, without disturbing it. This
  gives us a real event stream and makes the 5 second poll a fallback rather
  than the primary mechanism.
- **Bad:** if we ever *reply* to `PIN_Code_Request`, both we and `hcsecd` send a
  `PIN_Code_Reply` for the same request. The second one gets
  `Command_Disallowed` from the controller. Two agents cannot both answer.

**Decision for v1:** BluetoothMgr observes but never answers pairing events. It
keeps `hcsecd` as the pairing agent and drives it the way `bluetooth-config`
does, by writing `hcsecd.conf` and restarting the service. This is unglamorous
but it is the only way to coexist. See F6 for what that costs.

### F4. Secure Simple Pairing is not implemented anywhere in the tree. **[verified]**

This is the most significant finding and it is not mentioned in the brief.

- `hcsecd` listens for exactly three events: `PIN_Code_Request`,
  `Link_Key_Request`, `Link_Key_Notification`. Grepping its sources for
  `IO_CAPABILITY`, `USER_CONFIRM`, `SIMPLE_PAIR` or `ssp` returns nothing.
- The kernel receives `IO_CAPABILITY_REQUEST` and `SIMPLE_PAIRING_COMPLETE` and
  files them under "These do not need post processing", which frees the mbuf
  after passing it up to raw sockets. Nothing replies.
- `NG_HCI_IO_CAPABILITY_REQUEST_REPLY` and
  `NG_HCI_USER_CONFIRMATION_REQUEST_REPLY` exist as `#define`s in `ng_hci.h` and
  are referenced by **no code at all** in `sys/`, `lib/` or `usr.sbin/`.
- Nothing ever sends `Write_Simple_Pairing_Mode`, so SSP is never enabled on the
  controller and it falls back to legacy PIN pairing.

That is why the whole FreeBSD pairing experience is PIN-and-config-file shaped,
and why modern headsets behave badly. Bluetooth 2.1 shipped SSP in 2007. Devices
built since then expect "Just Works" or numeric comparison, and many have no PIN
at all.

This reframes a line in the audio journey document. The note about "hcsecd not
reliably persisting SSP link keys" is describing something real, but the naming
is off: since SSP is never enabled, every key on this system is a legacy pairing
key, not an SSP one. The actual persistence failure has a separate and much more
concrete cause, which is F7 below. Keep the two apart when debugging.

**Opportunity and risk.** Implementing SSP would make BluetoothMgr the first
thing on FreeBSD that pairs modern devices properly. The work is bounded: enable
SSP with `Write_Simple_Pairing_Mode`, then answer three events
(`IO_Capability_Request`, `User_Confirmation_Request`, optionally
`User_Passkey_Request`) and persist the key from `Link_Key_Notification`.

But it collides head on with F3. An SSP agent must own the pairing events, and
`hcsecd` is already sitting on `Link_Key_Request` and `Link_Key_Notification`.
You cannot have two.

**Decision:** scope SSP as **M6, explicitly experimental**, gated behind
a setting that also stops `hcsecd`. v1 ships the `hcsecd`-driven legacy flow so
we have something working end to end. Do not start here, but do not design
ourselves out of it either: keep the event listener and the pairing backend
behind an interface with two implementations.

### F5. Hotplug is already handled by `devd`. **[verified]**

`/etc/devd/bluetooth.conf`:

```
notify 100 { match "system" "USB"; match "subsystem" "DEVICE";
             match "type" "ATTACH"; device-name "ubt[0-9]+";
             action "service bluetooth quietstart $device-name"; };
```

plus the matching `DETACH` rule calling `quietstop`. So by the time a user could
possibly care, the netgraph stack is already built. The daemon does not need to
create nodes. It needs to *notice* and tell clients.

Two ways to notice. Polling `bt_devenum()` every 5 seconds is trivial and
already in the loop we need anyway. Connecting to devd's own socket at
`/var/run/devd.seqpacket.pipe` gives instant notification. Start with the poll,
add the devd socket later if the latency is annoying.

### F6. `hcsecd` has a query gap, but the reload hook exists. **[verified]**

`bluetooth-config.sh` carries two comments from its author:

```sh
# Since hcsecd does not allow querying for known devices, we need to
# check for bdaddr entries manually.
...
# TODO: hcsecd should provide a reload hook
/usr/sbin/service hcsecd onerestart
```

The first is true. The second is **stale**. `hcsecd` installs a `SIGHUP`
handler that does a full reload:

```c
sighup(int s)
{
        dump_keys_file();
        read_config_file();
        read_keys_file();
}
```

It dumps learned keys to disk *first*, then re-reads config and keys. The rc
script is plain `rc.subr` with a `pidfile`, so `service hcsecd reload` delivers
that `SIGHUP` and works today.

**Use `reload`, never `restart`.** A restart tears down the HCI socket and drops
any in-flight pairing. A reload preserves in-memory keys by flushing them first.
This matters more than it looks, because of F7.

So driving `hcsecd` means:

1. Parse `/etc/bluetooth/hcsecd.conf` ourselves, since it cannot be queried.
2. Regenerate it with the device block we need.
3. `service hcsecd reload`.

The file is parsed by a real lex/yacc grammar (`lexer.l`, `parser.y`). The
syntax is strict and the errors are poor, matching the "syntax error cost real
debugging time" note in the audio journey. **Our writer must be generate-only.**
Never attempt a surgical in-place edit. Parse into a list of device blocks, hold
it in memory, re-emit the whole file from our model preserving unknown keys per
block, write to a temp file and `rename()` it into place, keep one `.bak`.

Two things the real file on this machine tells us that the grammar does not:

- There is a **mandatory default entry** with `bdaddr 00:00:00:00:00:00`, and
  `get_key()` falls back to it for any unlisted device. Our generator must never
  drop it.
- The shipped file contains two `"Dummy"` example blocks
  (`00:01:02:03:04:05`, `00:11:22:33:44:55`) that are base-system boilerplate.
  Leave them alone. They are harmless, and "preserve what we did not write" is
  the rule that keeps us from destroying a hand-tuned config.

### F7. Link keys are silently discarded for any device not already in `hcsecd.conf`. **[verified]**

This is the root cause of the persistence problem described in the audio journey
document, and it is deterministic rather than flaky.

`get_key(bdaddr, exact_match)` walks the config-derived list. With
`exact_match == 0` it falls back to the default `00:00:00:00:00:00` entry. With
`exact_match == 1` it returns `NULL` when there is no exact block.

The three event handlers do **not** use the same value:

| Event | Call | Effect for an unlisted device |
|---|---|---|
| `PIN_Code_Request` | `get_key(bdaddr, 0)` | falls back to default entry, answers |
| `Link_Key_Request` | `get_key(bdaddr, 0)` | falls back to default entry, answers |
| `Link_Key_Notification` | `get_key(bdaddr, **1**)` | **`NULL`, key thrown away** |

`read_keys_file()` uses `exact_match == 1` as well, so even a key that did reach
`/var/db/hcsecd.keys` is dropped on the next start if its block is gone.

The observable behaviour is therefore exactly the reported symptom. Pairing an
unlisted device *appears* to succeed, because the default entry answers the PIN
request. The controller then sends `Link_Key_Notification`, `hcsecd` logs
"Could not find entry for remote bdaddr" and discards it, and the device needs
full re-pairing on next connect.

**Consequences for the design:**

- An explicit per-device block in `hcsecd.conf` is **mandatory** for key
  persistence. Not a nicety.
- Ordering is fixed: write the block, `service hcsecd reload`, *then* pair.
  Pairing first loses the key.
- This single behaviour is the most valuable thing BluetoothMgr automates. It is
  invisible from the CLI, the failure is silent, and the only evidence is a
  `LOG_ERR` line in syslog.
- `keys.c` should surface syslog's "Could not find entry" as a diagnosable
  condition, since it is the fingerprint of this exact bug.

Also worth noting for robustness: `dump_keys_file()` runs only on clean shutdown
and on `SIGHUP`. A `kill -9` or a panic loses every key learned since the last
reload. After a successful pairing, the daemon should issue a reload to force a
flush rather than trusting shutdown to happen cleanly.

### F8. The socket `bt_devenum()` hands its callback cannot be written to. **[verified]**

Found the hard way in M1: any `bt_devreq()` on that socket fails with `EPIPE`,
which raises `SIGPIPE` and kills the process by default. Reading and `ioctl()`
work normally, which is why it went unnoticed until the first HCI *command*.

The chain, all in base:

1. `bt_devenum()` binds and connects its socket to a dummy node `"x"` before
   the enumeration loop, so `soisconnected()` sets `SS_ISCONNECTED`.
2. Inside the loop it re-binds and re-**connects** that same socket to each
   real node.
3. `soconnectat()` sees `SS_ISCONNECTED`. Raw HCI is not `PR_CONNREQUIRED`, so
   rather than returning `EISCONN` it calls `sodisconnect()` first.
4. `ng_btsocket_hci_raw_disconnect()` calls `soisdisconnected()`, which runs
   `socantsendmore_locked()` and sets `SS_CANTSENDMORE`.
5. `pr_connect` then calls `soisconnected()`, which restores `SS_ISCONNECTED`
   but never clears `SS_CANTSENDMORE`.

The socket is therefore "connected" and permanently unwritable. This is a real
defect in the FreeBSD stack, not in `libbluetooth`'s caller.

**Consequences:**

- Any code in a `bt_devenum()` callback that needs to send an HCI command must
  open its own socket with `bt_devopen()`. `lib/libbtmgr/adapter.c` does this
  and carries a comment pointing here.
- The daemon MUST install `signal(SIGPIPE, SIG_IGN)` at startup regardless. A
  long-lived root daemon that dies on an unexpected `EPIPE` is unacceptable,
  and this is not the only socket it will hold.
- Worth an upstream bug report. The fix is presumably for
  `ng_btsocket_hci_raw_connect()` to clear the can't-send state, or for the
  raw HCI protocol to reject a second `connect()` outright.

---

## 4. Revised architecture

### 4.1 Component split

Unchanged from the brief in outline. The daemon is C, the MATE applet is C and
GTK3 against `libmatepanelapplet-4.0`, the settings window is C and GTK3, IPC is
JSON over a Unix socket. What changes is the daemon's internals.

```
bluetoothmgr/
├── lib/libbtmgr/            # NEW: the HCI layer, INTERNALLIB (static, not installed)
│   ├── btmgr.h              # the one public header
│   ├── adapter.c            # enumerate adapters, read name/scan/class
│   ├── conn.c               # connection list
│   ├── scan.c               # inquiry and remote name resolution
│   └── class.c              # class-of-device decode
├── common/                  # NEW: shared by daemon and all clients
│   ├── proto.c/.h           # JSON encode/decode of the IPC messages
│   └── ipc_client.c/.h      # connect, send, recv, reconnect. One copy.
├── daemon/src/
│   ├── main.c               # signals, event loop setup, privilege notes
│   ├── listen.c/.h          # NEW: passive HCI event listener (F3)
│   ├── ops.c/.h             # privileged: connect, disconnect, scan enable
│   ├── devices.c/.h         # the merged device model
│   ├── store.c/.h           # NEW: our own device database
│   ├── hosts.c/.h           # /etc/bluetooth/hosts read/write, aliases
│   ├── hcsecd.c/.h          # NEW: hcsecd.conf parse + regenerate
│   ├── keys.c/.h            # /var/db/hcsecd.keys read + delete
│   └── ipc.c/.h             # Unix socket server
├── tools/btmgr-probe/       # NEW: read-only CLI, M1. Links libbtmgr only.
├── applet-mate/src/
├── settings/src/
└── applet-indicator/src/    # later
```

New pieces relative to the brief, and why:

- **`lib/libbtmgr/`.** The brief put the HCI wrappers under `daemon/src/`, but
  they have two consumers with different privilege levels: `btmgr-probe`, which
  is unprivileged and daemon-free, and `bluetoothmgrd`. Per F2 the read-only
  half needs no root at all, so making it a separate static library keeps that
  boundary explicit rather than implicit. Built as `INTERNALLIB`, meaning a
  `.a` linked into each binary, never installed, no public ABI to maintain.
  Note this is a *build* boundary only. It does not replace the daemon, which
  still exists to hold the root privilege, serialise config writes, own the
  single event listener, and give all clients one consistent view of state.
- **`common/`.** The brief had `ipc_client.c` duplicated under each frontend.
  Three copies of a protocol parser will drift. One directory, built once,
  linked by everyone.
- **`listen.c`.** Falls out of F3. A second HCI socket with a wide event filter,
  added to the event loop as a readable fd. This is what turns the design from
  "poll and hope" into "event driven with a poll safety net".
- **`store.c`.** FreeBSD has no device database. `hcsecd.conf` holds pairing
  secrets, `/etc/bluetooth/hosts` holds aliases, `bthidd.conf` holds HID
  descriptors, and none of them holds "this is a headset, the user calls it
  Monster, last connected Tuesday". We need our own, at
  `/var/db/bluetoothmgr/devices.json`. This is the single biggest functional
  gap versus BlueZ.
- **`hcsecd.c`, `keys.c`, `hosts.c`.** Config ownership, per F6 and F7, plus
  the 32 character alias constraint. `hcsecd.c` owns the "block must exist
  before pairing" invariant from F7, which is the daemon's single most
  user-visible win.

### 4.2 The device model

The daemon merges four sources into one list. Understanding the merge is most of
understanding the daemon.

| Source | Contributes | Privilege |
|---|---|---|
| `SIOC_HCI_RAW_NODE_GET_CON_LIST` | who is connected *right now*, handle, role, encryption | none |
| `hcsecd.conf` + `hcsecd.keys` | who is paired, and the stored link key | root to read keys |
| `/etc/bluetooth/hosts` | the short alias, needed for the 32 char limit | none |
| `store.c` (ours) | type, user-visible name, last seen, auto-connect, audio settings | root |
| live inquiry | who is nearby but unknown, class of device, RSSI | none |

Keyed by BD_ADDR throughout. The `type` field in the IPC protocol comes from
decoding the class of device. The probe saw `28:04:3c` from "Basement TV 2":
major device class bits 8 to 12 give `0x04`, which is Audio/Video, and the
service class bits give rendering plus audio. That decode belongs in
`devices.c` as a small lookup table.

### 4.3 IPC protocol, revised

The brief's protocol is a good start but it is request/response only, and F3
gives us real events worth pushing. Add a framing rule and an event channel.

**Framing.** One JSON object per line, newline terminated. No length prefix, no
embedded newlines. This is trivial to parse with `getline()` and trivial to
debug with `nc -U`.

**Socket.** `/var/run/bluetoothmgr.sock`, mode `0660`, group `operator`. Clients
are desktop sessions, so group membership is the access control. Reject commands
that change state if the peer is not in the group, checked with `getpeereid()`.

Commands, client to daemon:

```json
{"id": 1, "cmd": "get_state"}
{"id": 2, "cmd": "set_power", "on": true}
{"id": 3, "cmd": "set_discoverable", "timeout": 180}
{"id": 4, "cmd": "scan", "action": "start", "duration": 10}
{"id": 5, "cmd": "connect", "addr": "00:11:22:33:44:55"}
{"id": 6, "cmd": "disconnect", "addr": "00:11:22:33:44:55"}
{"id": 7, "cmd": "pair", "addr": "00:11:22:33:44:55", "pin": "0000"}
{"id": 8, "cmd": "remove", "addr": "00:11:22:33:44:55"}
{"id": 9, "cmd": "set_alias", "addr": "00:11:22:33:44:55", "alias": "z337"}
```

Every command carries an `id`. Every reply echoes it. Without this, a client
with two requests in flight cannot tell which reply is which.

Replies and events, daemon to client:

```json
{"id": 5, "ok": false, "error": "stale_link_key",
 "detail": "Device rejected stored key. Remove pairing and retry?"}

{"event": "state", "adapter_present": true, "powered": true,
 "discoverable": false, "scanning": false,
 "adapter": {"addr": "00:1a:7d:da:71:13", "name": "ericbsd-ghostbsd-pc"},
 "devices": [
   {"addr": "0f:44:53:d2:d7:88", "name": "Monster", "alias": "headphones",
    "type": "headset", "connected": false, "paired": true, "trusted": true}
 ]}

{"event": "device_added",  "device": {...}}
{"event": "device_removed","addr": "..."}
{"event": "pairing_pin_needed", "addr": "...", "name": "..."}
```

Note `"error": "stale_link_key"`. Machine readable error codes matter here,
because the recovery for that specific case is "delete the entry from
`/var/db/hcsecd.keys` and re-pair", which the settings window should offer as a
button rather than making the user find it in a forum post.

### 4.4 The event loop

**Resolved:** use **raw `kevent`** in the daemon, not `g_timeout_add_seconds`.

The brief listed this as an open decision. The case for `kevent`:

- The daemon has no GUI and no GObject types. Linking GLib into a root daemon to
  get a timer is a large dependency for a small feature.
- We already need `kevent` semantics. `EVFILT_READ` on the listener socket, on
  the IPC listen socket, and on each client fd, plus `EVFILT_TIMER` for the poll
  fallback, plus `EVFILT_SIGNAL` for clean `SIGTERM` and `SIGHUP` handling.
- `EVFILT_SIGNAL` in particular is the thing GLib cannot do as cleanly. It turns
  signals into ordinary queue entries and eliminates the whole
  `volatile sig_atomic_t` dance.
- It is the right thing to learn. `kqueue` is the native FreeBSD event
  interface and it generalises to every other daemon in this ecosystem.

The clients still use GTK's main loop, because they are GTK apps. They watch the
daemon socket with `g_unix_fd_add()`. Different loops on each side is fine, the
socket is the boundary.

Poll interval: keep 5 seconds as a reconciliation pass, not as the primary
mechanism. Events drive updates. The timer catches anything missed, and detects
adapter hotplug.

---

## 5. C learning track

The project is arranged so the C concepts arrive in a useful order rather than
all at once. Each milestone in section 6 introduces a named set.

### 5.1 Concepts, in the order they show up

**M1, the daemon skeleton.** `struct` layout and padding. Pointers and the
difference between `T *p` and `T p[]`. `const` on parameters as documentation.
Header guards and the `.c`/`.h` split. `static` for file-private functions.
Compiling and linking with `cc -Wall -Wextra`.

**M1, talking to libbluetooth.** The errno convention. The callback pattern.
Out-parameters and ownership.

**M2, parsing HCI.** Pointer arithmetic on struct pointers. `__attribute__((packed))`.
Byte order.

**M3, the event loop.** File descriptors. `kqueue`. Non-blocking IO and partial
reads.

**M4, the GTK client.** Opaque pointers and GObject. Reference counting. Callbacks
with user data.

### 5.2 Three idioms worth understanding before we start

These three account for most of the code in `lib/libbluetooth` and
`usr.sbin/bluetooth`, so being fluent in them makes the whole tree readable.

**Idiom 1: header plus payload, via `(ptr + 1)`.**

From `bt_devreq()` in `lib/libbluetooth/hci.c`:

```c
uint8_t                  buf[320];
ng_hci_event_pkt_t      *e  = (ng_hci_event_pkt_t *) buf;
ng_hci_command_compl_ep *cc = (ng_hci_command_compl_ep *)(e + 1);
```

`buf` is 320 raw bytes off the wire. The first line says "treat the start of
this buffer as an event header". The second line is the important one.

`e` has type `ng_hci_event_pkt_t *`. In C, adding 1 to a pointer advances it by
`sizeof(*e)` bytes, not by 1 byte. So `e + 1` points to the byte immediately
after the header, which is exactly where the payload starts. The cast then says
"and treat *that* as a command-complete payload".

It is the C way of writing `buf[sizeof(header):]` without copying anything. You
will see it on every wire protocol in the tree. The thing to watch is that it is
entirely unchecked: nothing stops you casting past the end of a short packet,
which is why `bt_devrecv()` validates `n == sizeof(*h) + h->length` before anyone
looks at the payload.

**Idiom 2: the enumerate-with-callback.**

```c
typedef int (bt_devenum_cb_t)(int, struct bt_devinfo const *, void *);
int bt_devenum(bt_devenum_cb_t cb, void *arg);
```

`bt_devenum` does not return a list. It calls *your* function once per adapter.
The `void *arg` is passed through untouched, which is how you smuggle your own
context in, since the callback cannot capture variables the way a closure would.

Our probe used it like this:

```c
static int
on_device(int s, struct bt_devinfo const *di, void *arg)
{
        (void)arg;              /* unused, silence -Wunused-parameter */
        printf("node: %s\n", di->devname);
        return (0);             /* 0 = keep going, >0 = stop early */
}

bt_devenum(on_device, NULL);
```

`const` on `di` is a promise that the callback will not modify it. `(void)arg;`
is the idiom for deliberately ignoring a parameter without a compiler warning.

**Idiom 3: errno, and why functions return -1.**

Nearly every function here returns `int`, where 0 or a count means success and
-1 means failure, with the actual reason in the global `errno`. So:

```c
s = bt_devopen("ubt0hci");
if (s < 0) {
        /* check errno NOW, before any other call can overwrite it */
        fprintf(stderr, "bt_devopen: %s\n", strerror(errno));
        return (1);
}
```

Two rules. Read `errno` immediately, because the next library call may clobber
it even if it succeeds. And only read it after a call actually signalled
failure, because a successful call is allowed to leave garbage there.

Our own code should follow the same convention internally, so it composes with
everything around it.

---

## 6. Build order

Each milestone ends with something runnable and testable.

Checklists distinguish **written** from **verified**, and verified on hardware
from verified synthetically. That distinction has already earned its keep
twice: `listen.c` passed every synthetic test while never having seen a real
HCI event, and F7 is asserted in three documents on the strength of source
reading alone.

### M0. Repo scaffolding
Directory tree, BSD `Makefile`s using `bsd.prog.mk` and `bsd.lib.mk`,
`.gitignore`, and `tools/probe/` committed with the three probe programs so the
datapoint is reproducible on other hardware. Folded into M1, since on its own
it produces nothing runnable.

### M1. `libbtmgr` plus `btmgr-probe`, a read-only CLI **[done]**
Not in the brief, but it is the right first step. Build `lib/libbtmgr`
(`adapter.c`, `conn.c`, `scan.c`, `class.c`) and a single binary that prints
adapter state, the connection list, and a scan. It needs no root, no event loop,
no IPC and no config files, so it isolates the libbluetooth layer completely.
When this is clean, the hardest unknowns are gone. This is also where the C
fundamentals in 5.1 land.

API conventions fixed here and followed by every module after:

- **Caller provides the array.** Every list has a hard kernel-side bound
  (`HCI_DEVMAX`, `NG_HCI_MAX_CON_NUM`, our own scan cap), so functions take
  `(struct T *out, int *n)` where `*n` is capacity in and count out. This is the
  same in/out convention the kernel ioctls use. M1 therefore performs no heap
  allocation at all, which makes heap ownership a deliberate topic in M2 rather
  than an accident in M1.
- **Our structs, not libbluetooth's.** `struct btmgr_adapter` and
  `struct btmgr_device` mirror `SPEC.md` B5, not `struct bt_devinfo`. The copy
  buys a boundary so the wire protocol is not hostage to a kernel header.
- **Return `int`, 0 on success, -1 with `errno` on failure.** Matches
  `libbluetooth` exactly, so our code composes with it without translation.

**Checklist**

- [x] `lib/libbtmgr` as `INTERNALLIB`, built `-fPIC` so it links into PIE
- [x] `adapter.c`, `conn.c`, `scan.c`, `class.c`
- [x] `btmgr-probe` with `adapter` / `conn` / `scan` views
- [x] Clean under `-Wall -Wextra -Wshadow -Wstrict-prototypes`
      `-Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wwrite-strings`
- [x] Verified on hardware: adapter state, connection list, live scan
- [x] Verified on hardware: class decode on two devices, covering both a
      specific mapping (Z337 `24:04:14`, Loudspeaker) and the fallback
      (TV `28:04:3c`)

### M2. Daemon core **[done]**
`main.c` with a `kqueue` loop, `EVFILT_SIGNAL` for `SIGTERM`/`SIGHUP`,
`EVFILT_TIMER` for the 5 second reconcile, and `listen.c` on `EVFILT_READ`.
`ipc.c` serves `get_state` and pushes `state` events. rc.d script included.
Test with `nc -U /var/run/bluetoothmgr.sock`.

Deliberately unprivileged, so it runs as an ordinary user during development:

```sh
./daemon/bluetoothmgrd -f -s /tmp/btmgr.sock
nc -U /tmp/btmgr.sock
```

Decisions made while building it:

- **Non-blocking writes with `EVFILT_WRITE` and drop-on-overflow**, rather than
  blocking writes. A blocking write to a client that stopped reading would hang
  the daemon, which for a root daemon means Bluetooth stops working
  machine-wide because somebody suspended an applet. Output over
  `IPC_OUT_MAX` drops that client.
- **Input framing via an explicit `in_taken` offset.** The line handed to the
  caller points into the input buffer with no copy, so the buffer cannot be
  compacted until the caller is done with it. Compacting at the start of the
  *next* call is what makes "valid until the next call" literally true.
- **Coalescing by snapshot comparison.** `state_equal()` compares field by
  field rather than `memcmp()`, because struct padding bytes nobody set would
  otherwise make every tick look like a change.
- **`scan` is not an IPC command yet.** Driving inquiry from the event loop
  means an asynchronous inquiry rather than the blocking `bt_devinquiry()` that
  `libbtmgr` uses today. That is real work and belongs in its own step.

**Checklist**

- [x] `kqueue` loop over `EVFILT_READ`, `WRITE`, `SIGNAL`, `TIMER`
- [x] `listen.c`, passive HCI listener that never replies (F3)
- [x] `ipc.c`, line framing, non-blocking both directions, drop-on-overflow
- [x] `proto.c` over jansson, shared by daemon and future clients
- [x] `state.c`, snapshot plus field-wise diff for coalescing
- [x] rc.d script, and `-f` / `-s` flags for unprivileged development
- [x] `SIGPIPE` ignored at startup (F8)
- [x] Verified synthetically: split lines, batched lines, 70 KiB oversized
      line, 40 rapid reconnects, `SIGHUP`, `SIGTERM`, multiple clients
- [x] Verified under AddressSanitizer: no memory errors
- [x] Verified on hardware: `Connection_Complete` and `Disconnection_Complete`
      each drive an immediate `state` event, fields cross-checked against
      `hccontrol`, and no spurious broadcast across several timer ticks
- [x] Leak check: `make analyze` (clang static analyzer) plus
      `make memcheck` (allocation tracker). 117 allocations across every
      path, 0 live at exit. Tracker validated by introducing a deliberate
      leak, which it caught and clang did not

### M3a. Privileged HCI operations
`connect`, `disconnect`, `set_discoverable`. Root required, but no file is
written, so the blast radius is a device that fails to connect. Doing this
before M3b means the root-related bugs surface while nothing can be damaged.

The central problem is that `Create_Connection` returns `Command_Status`
immediately and `Connection_Complete` seconds later, up to the full page
timeout when a device is off. Blocking in `bt_devreq()` would stall the entire
event loop, so one unreachable speaker would freeze Bluetooth machine-wide.
Instead the command is sent without waiting, the request is recorded in a small
in-flight table, and the reply is delivered when the passive listener sees the
completion. The listener built in M2 for state updates becomes the completion
channel for asynchronous commands.

**Checklist**

- [x] `btmgr_connect_start`, `btmgr_disconnect_start`, `btmgr_set_scan` in
      `lib/libbtmgr`, not `daemon/src/ops.c`: the library boundary is "talks
      HCI", not "is unprivileged", and keeping them together allows CLI testing
- [x] `btmgr-probe connect|disconnect|discoverable`, exercising all three with
      no daemon involved
- [x] `listen.c` parses the `Connection_Complete` payload for bdaddr and status
- [x] In-flight operation table: bounded at 8, per-entry deadline checked on
      the existing tick, `busy` when full, `timeout` on expiry, and entries
      dropped when their client disconnects
- [x] Async `connect`: the reply arrives on completion, not on send
- [x] `set_discoverable` reverts via a one-shot `EVFILT_TIMER`
- [x] `SPEC.md` A5.3 privilege check, **including supplementary groups**.
      `getpeereid()` reports only the peer's primary gid while the kernel
      admits a connection on any of its groups, so a primary-gid-only check
      refuses precisely the intended deployment (socket group `operator`,
      users added to `operator` supplementarily)
- [x] Verified unprivileged: every state-changing verb reaches the HCI layer
      and fails with `EPERM`, rather than being refused by our own check
- [x] Clean under the strict warning set, the static analyzer, and `memcheck`
      (86 allocations, 0 live)
- [x] Verified on hardware: a **failed** connect reports a usable status and
      the right bdaddr. Measured: connecting to an absent address returned
      `io_error`, "controller reported status 0x04" (Page timeout), at
      **5.14s**. The completion carried a usable bdaddr and we correlated it
      by address, so `inflight.c` stands as written
- [x] Verified on hardware: connect and disconnect driven through IPC as root.
      A Logitech Z337 connected in **0.21s** and **0.29s** across two runs,
      handle 72, ACL, master. The `state` event carried the connection ~0.04s
      later, and `disconnect` resolved the address against it and replied `ok`
      in **0.08s**, exercising the handle lookup
- [x] Verified on hardware: the in-flight timeout fires when a device never
      answers. Note this needed provoking: the controller *does* answer for an
      absent device, in 5.12s, so no ordinary connect can reach the 20s
      deadline. Resetting the controller a second after a connect drops the
      pending page without reporting it, and the reply was `timeout`, "no
      completion from the controller", at **19.57s**

Deliberately excluded: `write_authentication_enable`. The audio journey shows
it is required before `virtual_oss` can open A2DP, but it belongs with the
audio work in M7 rather than shipping as a toggle nobody can test.

### M3b. Config ownership
`hosts.c`, `hcsecd.c`, `keys.c`, `store.c`. This is the half that can damage a
working setup, which is why `SPEC.md` Part A was written before any of it.

**Checklist**

- [ ] `hosts.c`: parse, generate aliases, 16 character budget (A2.3),
      collision suffixes, preserve records we did not write
- [ ] `hcsecd.c`: parse the lex/yacc grammar, regenerate whole, preserve the
      mandatory default entry and every block we did not author (A1)
- [ ] `keys.c`: read `/var/db/hcsecd.keys`, delete for stale key recovery,
      never log or transmit key material (A3)
- [ ] `store.c`: `/var/db/bluetoothmgr/devices.json`, no secrets (A4)
- [x] A0 write discipline: atomic rename, one `.bak` per boot, never edit in
      place, never write when the content is unchanged. `common/safefile.c`,
      verified by `tools/btmgr-filetest`: 30 checks, no root or hardware
      needed. A0.3 and A0.4 stay with the callers, since this layer only ever
      sees a finished buffer
- [ ] A6 pairing order enforced: write the block, reload, *then* pair
- [ ] A7 sanitisation of every device-supplied string
- [ ] `--dry-run` and a config-directory override, so the whole thing can be
      exercised against copies in `/tmp` before it touches `/etc`
- [ ] Verified on hardware: **F7 reproduced.** Pairing a device with no block
      in `hcsecd.conf` logs "Could not find entry for remote bdaddr" and the
      key is discarded. This is the claim the README rests on and it is still
      source reading only
- [ ] Verified on hardware: a device paired through the daemon survives a
      reboot without re-pairing

### M4. MATE panel applet
`libmatepanelapplet-4.0` skeleton, popup with a toggle and device list,
show/hide bound to `adapter_present`, and a "Preferences…" item. Uses
`common/ipc_client.c` unchanged.

**Checklist**

- [ ] `common/ipc_client.c`, the client half of the protocol, shared by every
      frontend
- [ ] Applet skeleton, popup, icon states: absent, off, on, connected
- [ ] Show and hide driven by `adapter_present`
- [ ] Reconnect when the daemon restarts under it
- [ ] Verified: hotplug the dongle and watch the applet appear and disappear

### M5. Settings window
`bluetoothmgr-settings`, the pairing wizard, device management, alias editing,
`hcsecd` key management, and the `.desktop` file for the Administration menu.

**Checklist**

- [ ] Pairing wizard driving the A6 sequence
- [ ] Device list: rename, remove, trust
- [ ] Alias editing bounded by A2.3
- [ ] One-click stale key recovery, the `stale_link_key` path from B6.1
- [ ] `.desktop` entry for the Administration menu

### M6. SSP, experimental
Per F4. Behind a setting, mutually exclusive with `hcsecd`. Treat as research.

**Checklist**

- [ ] Refuse to arm while `hcsecd` is running
- [ ] `Write_Simple_Pairing_Mode` to enable SSP
- [ ] Answer `IO_Capability_Request` and `User_Confirmation_Request`
- [ ] Persist the key from `Link_Key_Notification`
- [ ] Verified: pair a device that has no PIN at all

### M7. Audio integration
`virtual_oss` supervision, `pactl` module loading, and the null-sink plus
loopback volume workaround. Everything from the audio journey document.

**Checklist**

- [ ] `write_authentication_enable` as part of the audio connect flow
- [ ] `virtual_oss` supervision
- [ ] `pactl` module loading, since PulseAudio does not detect CUSE devices
- [ ] Volume via null-sink plus loopback
- [ ] Verified: the whole audio journey reproduced with no manual steps

### M8. AppIndicator/SNI frontend
XFCE, KDE and Cinnamon, reusing `common/`.

**Checklist**

- [ ] SNI frontend against the same daemon and protocol
- [ ] `ACTIVE`/`PASSIVE` on adapter presence
- [ ] Verified on at least one non-MATE desktop

---

## 7. Decisions

Resolved from the brief's open list:

- **`poll.c` timer mechanism.** Raw `kevent`, no GLib in the daemon. Section 4.4.
- **`bthidd` management.** Manual toggle in the settings window for v1.
  Automatic management means restarting `bthidd`, which drops the connection to
  a Bluetooth keyboard, which is exactly the input device the user may be typing
  on. `bluetooth-config.sh` warns about this for the same reason. Offer it, do
  not impose it.
- **Applet icon states.** Four: `absent` (hidden entirely), `off`, `on`,
  `connected`. `scanning` becomes an animation or overlay on `on` rather than a
  fifth state, because scanning is transient and the user still needs to know
  whether anything is connected.

Resolved but not previously listed:

- **JSON library.** `jansson`. It is already in the tree, it is plain C with no
  GLib dependency, so `common/` links into the GLib-free daemon and the GTK
  clients alike. `json-glib` would drag GLib into the daemon, which contradicts
  4.4.
- **"powered" semantics.** FreeBSD has no adapter power control. Map `powered`
  to whether the netgraph stack is attached, and `set_power` to
  `service bluetooth start|stop ubt0`. Document this, because it is a real
  behavioural difference from BlueZ: powering off here tears down the stack.

Still open:

- Whether `store.c` should be JSON or a flat text format. JSON is consistent with
  the IPC layer and we are linking jansson anyway. Leaning JSON.
- Whether the settings window should expose `write_authentication_enable` as a
  visible toggle or just do it during connect for audio devices. Leaning
  automatic, with an advanced override, since the audio journey shows it is
  required and never optional.

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| SSP absence blocks modern devices | high. Many headsets simply will not pair | scope as M6, be explicit in docs that v1 is legacy pairing |
| `hcsecd` coexistence is fragile | medium. Restarting it drops in-flight pairing | never edit its config in place, always regenerate plus `.bak`, and use `service hcsecd reload` (SIGHUP), never `restart` |
| Link key discarded for unlisted device (F7) | high. Silent, and forces re-pairing every session | guarantee the config block exists and reload before pairing is attempted, never after |
| Firmware clearing pairing on disconnect | medium. Monster headphones do this | detect the reconnect failure, offer one-click key delete plus re-pair |
| Two pairing agents if a user starts `hcsecd` during M6 | high. Both reply, controller errors | M6 setting must stop and disable `hcsecd`, and the daemon should refuse to arm SSP while `hcsecd` is running |
| MATE applet API churn | low | pinned by the `libmatepanelapplet-4.0` package already installed |
| Daemon dies on SIGPIPE (F8) | medium. A raw HCI write can return EPIPE unexpectedly | `signal(SIGPIPE, SIG_IGN)` at daemon startup, and check every write's return |
| Root daemon attack surface | medium | line-oriented JSON with hard length caps, `getpeereid()` check, no shell interpolation of any device-supplied string |

The last one deserves emphasis. Remote device names arrive from untrusted
hardware and end up in `hcsecd.conf` and `/etc/bluetooth/hosts`.
`bluetooth-config.sh` already sanitises with `tr -c '[:alnum:]-,.' _` for this
reason. Our writer must do at least as much, and must never build a shell
command by string concatenation with a device name in it.
