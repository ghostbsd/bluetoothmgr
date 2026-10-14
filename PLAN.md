# BluetoothMgr: implementation plan

Behavior is defined in `SPEC.md`. This file covers how it is built and in what
order. Tick items as they are completed.

## Toolchain

C, built with Clang, the FreeBSD base compiler. BSD make with `bsd.prog.mk` and
`bsd.lib.mk`, so the tree builds with nothing but base.

`make tidy` runs clang-tidy with `WarningsAsErrors` set and is the gate before a
commit. It compiles without linking, so `make` must pass separately: tidy cannot
see an undefined symbol. `make memcheck` rebuilds the daemon with an allocation
tracker that reports anything still live at exit. Each harness under `tools/`
exits non-zero on a failed check.

HCI access goes through `libbluetooth`, never a hand-rolled raw socket.
`bt_devopen`, `bt_devreq`, `bt_devenum` and `bt_devinquiry` already wrap the
netgraph ioctls, with the one trap in `SPEC.md` C4.

## Dependencies

`libbluetooth` and netgraph from base, `jansson`, plus `gtk+-3.0` and
`libmatepanelapplet-4.0` for the applet (M4) and the settings window (M5).

jansson rather than json-glib, because it is plain C: `common/` links into the
GLib-free daemon and the GTK clients alike. The daemon has no GLib and no
GObject types, and its event loop is raw `kqueue`.

## Module layout

| Module | Role |
|---|---|
| `lib/libbtmgr/adapter.c` | Adapter enumeration, name, scan state, class |
| `lib/libbtmgr/conn.c` | Connection list |
| `lib/libbtmgr/scan.c` | Inquiry and remote name resolution |
| `lib/libbtmgr/class.c` | Class-of-device decode to the `SPEC.md` B5.3 vocabulary |
| `lib/libbtmgr/ops.c` | Privileged HCI: connect, disconnect, scan enable, authenticate |
| `common/proto.c` | JSON encode and decode of every IPC message (B1 to B7) |
| `common/ipc_client.c` | The client half: connect, request, dispatch, reconnect |
| `common/linebuf.c` | Buffered line I/O over one non-blocking fd |
| `common/safefile.c` | The A0 write discipline: atomic rename, one `.bak` per boot |
| `common/hcsecd.c` | `hcsecd.conf` parse and whole-file regenerate (A1) |
| `common/keys.c` | `/var/db/hcsecd.keys` read and record delete (A3) |
| `common/hosts.c` | `/etc/bluetooth/hosts` read and write, alias generation (A2) |
| `common/store.c` | `/var/db/bluetoothmgr/devices.json`, our own metadata (A4) |
| `common/sanitise.c` | Device-supplied strings made safe (A7, B1.4) |
| `common/hcsecdctl.c` | `hcsecd` process lookup and `SIGHUP` (A8.1) |
| `common/pairing.c` | The A6 ordering as a parked state machine |
| `common/paths.c` | Path construction and the config-directory override |
| `daemon/src/main.c` | Signals, `kqueue` loop, command dispatch, authorization |
| `daemon/src/ipc.c` | Unix socket server (A5) |
| `daemon/src/listen.c` | Passive HCI event listener (C2) |
| `daemon/src/inflight.c` | In-flight table for commands answered by a later event |
| `daemon/src/state.c` | Snapshot of the world, plus field-wise diff for coalescing |
| `tools/btmgr-probe/` | Read-only CLI, no daemon, no root for the read half |
| `tools/btmgr-*test/` | Unit harnesses, no root and no hardware |

The daemon exists to hold root, serialise config writes, own the single event
listener, and give every client one consistent view of state. `lib/libbtmgr` is
an `INTERNALLIB`, a `.a` linked into each consumer and never installed, built
`-fPIC` so it links into a PIE. It is a build boundary, not a privilege one:
per `SPEC.md` C1.3 the read half needs no root, which keeps a later split into
a root helper plus an unprivileged poller open.

`common/` is shared rather than copied per frontend, because three copies of a
protocol parser drift.

### API conventions

Fixed in M1 and followed by every module since.

- **The caller provides the array.** Every list has a hard kernel-side bound
  (`HCI_DEVMAX`, `NG_HCI_MAX_CON_NUM`, our own scan cap), so functions take
  `(struct T *out, int *n)` with `*n` capacity in, count out, matching the
  ioctls themselves.
- **Our structs, not `libbluetooth`'s.** `struct btmgr_adapter` and
  `struct btmgr_device` mirror `SPEC.md` B5, so the wire protocol is not
  hostage to a kernel header.
- **Return `int`, 0 on success, -1 with `errno`.** Matches `libbluetooth`, so
  our code composes with it without translation.

### The device model

The daemon merges five sources into one list, keyed by BD_ADDR throughout.

| Source | Contributes | Privilege |
|---|---|---|
| `SIOC_HCI_RAW_NODE_GET_CON_LIST` | who is connected now, handle, role, encryption | none |
| `hcsecd.conf` plus `hcsecd.keys` | who is paired, and whether a key is stored | root to read keys |
| `/etc/bluetooth/hosts` | the short alias, within the A2.3 budget | none |
| `common/store.c` | type, user-visible name, last seen, auto-connect | root |
| live inquiry | who is nearby but unknown, class of device, RSSI | none |

`paired` and `has_key` come from different files and MUST stay separate, per
B5.2. That difference is the A3.4 failure mode.

## M1: libbtmgr and a read-only CLI

- [x] `lib/libbtmgr` as `INTERNALLIB`, built `-fPIC` so it links into a PIE
- [x] `adapter.c`, `conn.c`, `scan.c`, `class.c`
- [x] `btmgr-probe` with `adapter` / `conn` / `scan` views
- [x] Clean under `-Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wcast-qual -Wwrite-strings`
- [x] Verified on hardware: adapter state, connection list, live scan
- [x] Verified on hardware: class decode on two devices, covering a specific mapping and the fallback
- [x] Verified: the privilege boundary of C1, every read-side call as an ordinary user and the first `EPERM`

## M2: Daemon core

- [x] `kqueue` loop over `EVFILT_READ`, `WRITE`, `SIGNAL`, `TIMER`
- [x] `listen.c`, passive HCI listener that never replies (C2)
- [x] `ipc.c`, line framing, non-blocking both directions, drop-on-overflow
- [x] `proto.c` over jansson, shared by daemon and clients
- [x] `state.c`, snapshot plus field-wise diff for coalescing (B7.1)
- [x] rc.d script, and `-f` / `-s` flags for unprivileged development
- [x] `SIGPIPE` ignored at startup (C4.2)
- [x] Verified synthetically: split lines, batched lines, 70 KiB oversized line, 40 rapid reconnects, `SIGHUP`, `SIGTERM`, multiple clients
- [x] Verified under AddressSanitizer: no memory errors
- [x] Verified on hardware: `Connection_Complete` and `Disconnection_Complete` each drive an immediate `state` event, cross-checked against `hccontrol`, with no spurious broadcast across several timer ticks
- [x] Leak check: `make memcheck`, 117 allocations across every path, 0 live at exit, the tracker itself validated with a deliberate leak

## M3a: Privileged HCI operations

- [x] `btmgr_connect_start`, `btmgr_disconnect_start`, `btmgr_set_scan` in `lib/libbtmgr`, so they are testable from the CLI with no daemon
- [x] `btmgr-probe connect|disconnect|discoverable`
- [x] `listen.c` parses the `Connection_Complete` payload for bdaddr and status
- [x] In-flight table: bounded at 8, per-entry deadline on the existing tick, `busy` when full, `timeout` on expiry, entries dropped when their client disconnects
- [x] Async `connect`: the reply arrives on completion, not on send
- [x] `set_discoverable` reverts via a one-shot `EVFILT_TIMER`
- [x] Verified on hardware: a failed connect reports a usable status and the right bdaddr. An absent address returned `io_error`, page timeout, at 5.14s
- [x] Verified on hardware: connect and disconnect through IPC as root, 0.21s and 0.29s, the `state` event ~0.04s later, `disconnect` resolving the address against it in 0.08s
- [x] Verified on hardware: the in-flight timeout fires when the controller never answers, provoked with a controller reset, `timeout` at 19.57s
- [x] Verified unprivileged: every state-changing verb reaches the HCI layer and fails with `EPERM` there, rather than being refused by our own check. Predates A5.3, which will refuse them earlier
- [x] Clean under the strict warning set, the static analyzer, and `memcheck`: 86 allocations, 0 live

## M3b: Config ownership

- [x] `hosts.c`: parse, generate aliases within the 16 character budget (A2.3), collision suffixes, preserve records we did not write
- [x] `hcsecd.c`: parse the lex/yacc grammar, regenerate whole, preserve the default entry and every block we did not author (A1)
- [x] `keys.c`: read `/var/db/hcsecd.keys`, delete a record, never log or transmit key material (A3)
- [x] `store.c`: `/var/db/bluetoothmgr/devices.json`, no secrets (A4)
- [x] A0 write discipline in `common/safefile.c`: atomic rename, one `.bak` per boot, never edit in place, never write unchanged content
- [x] A6 ordering as a module, `common/pairing.c`, a parked state machine spanning the asynchronous gap
- [x] A8.1 and A8.2 service control in `common/hcsecdctl.c`
- [x] A6 wired into the daemon: the `pair` command, the parked state with a timeout, per-link authentication (A6.5), and B4.7
- [x] A7 sanitisation of every device-supplied string, `common/sanitise.c`
- [x] B1.4: invalid UTF-8 in a reported name replaced rather than fatal
- [x] `--dry-run` and a config-directory override, so the whole thing runs against copies before it touches `/etc`
- [x] Verified on hardware: A3.4 reproduced, pairing a device with no `hcsecd.conf` block discards the key
- [x] Verified on hardware: a device paired through the daemon survives a reboot without re-pairing

## M4: MATE panel applet

- [x] `common/ipc_client.c`, the client half of the protocol, with `common/linebuf.c` underneath it
- [ ] A5.3 and A9: refuse every command unless the peer is root or its process belongs to a GUI session, from `getsockopt(LOCAL_PEERCRED)` and `getutxent()`. Replaces the socket-group check M3a built
- [ ] Decode the `connections` array in `proto_parse_msg()`, which today counts it and discards it, so a frontend can list devices
- [ ] Applet skeleton, popup, icon states: absent, off, on, connected
- [ ] Show and hide driven by `adapter_present`
- [ ] Reconnect when the daemon restarts under it
- [ ] Verified: hotplug the dongle and watch the applet appear and disappear
- [ ] Manual test by maintainer

## M5: Settings window

Also the milestone that connects the device model: `common/store.c`,
`keys_remove()` and `btmgr_class_type()` are written and tested but have no
caller in the daemon, so the `devices` array of every `state` event is empty.

- [ ] `scan` as an IPC command, asynchronous inquiry driven from the event loop, idempotent per B4.2, results as `device_found` events
- [ ] `remove`, `set_alias`, `set_trusted` and `set_power` commands (A8.5)
- [ ] Wire `common/store.c` into the daemon, so A4 metadata reaches clients
- [ ] Populate the `devices` array: `paired`, `has_key`, `type`, `class`, `connected`, `trusted` (B5.2, B5.3)
- [ ] `rssi`, null unless the device was seen in the current scan (B5.4)
- [ ] `device_added` and `device_removed` events on store changes (B7)
- [ ] `pairing_progress` events for the A6 stage transitions (B7)
- [ ] Pairing wizard driving the A6 sequence
- [ ] Device list: rename, remove, trust
- [ ] Alias editing bounded by A2.3, refused with `alias_too_long`
- [ ] One-click stale key recovery: the `stale_link_key` code and the A3.2 delete, which needs `hcsecd` stopped
- [ ] `.desktop` entry for the Administration menu
- [ ] Manual test by maintainer

## M6: SSP, experimental

Per `SPEC.md` C5. Behind a setting, mutually exclusive with `hcsecd` per C2.2.
Treat as research.

- [ ] Refuse to arm while `hcsecd` is running
- [ ] `Write_Simple_Pairing_Mode` to enable SSP
- [ ] Answer `IO_Capability_Request` and `User_Confirmation_Request`
- [ ] Persist the key from `Link_Key_Notification`
- [ ] Verified: pair a device that has no PIN at all
- [ ] Manual test by maintainer

## M7: Audio integration

- [ ] Test whether the per-link `Authentication_Requested` of A6.5 is enough for `virtual_oss` before adding any adapter-wide toggle
- [ ] `write_authentication_enable` as part of the audio connect flow, if A6.5 proves insufficient
- [ ] `virtual_oss` supervision
- [ ] `pactl` module loading, since PulseAudio does not detect CUSE devices
- [ ] Volume via null-sink plus loopback
- [ ] Confirm the A2.3 alias budget against the `virtual_oss` source, which was not available when 16 was chosen
- [ ] Verified: the whole audio journey reproduced with no manual steps
- [ ] Manual test by maintainer

## M8: AppIndicator/SNI frontend

- [ ] SNI frontend against the same daemon and protocol, reusing `common/`
- [ ] `ACTIVE` / `PASSIVE` on adapter presence
- [ ] Verified on at least one non-MATE desktop
- [ ] Manual test by maintainer
