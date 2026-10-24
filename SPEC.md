# BluetoothMgr — Specification

Companion to `PLAN.md`. The plan carries the build order. This document carries
the contract, and the platform constraints that contract rests on.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

| Part | Scope | Status |
|---|---|---|
| A | On-disk files and operation ordering | **Normative.** Verified against `../ghostbsd-src`. Stable. |
| B | IPC protocol | **v0, provisional.** Freezes at M2 when `ipc.c` exists. |
| C | Platform constraints of the base Bluetooth stack | **Normative.** Verified against `../ghostbsd-src` and by measurement. |

Out of scope by design: audio integration (M4), SSP (M5) and the UI behaviour
of the frontends (M6 to M8). Speccing them now would be writing fiction.

---

# Part A — Files and ordering (normative)

BluetoothMgr writes to files that predate it, that the user may have edited by
hand, and that other daemons parse with strict grammars. Part A exists because
getting any of this wrong either corrupts a working configuration or silently
loses pairing keys.

## A0. Rules that apply to every file we write

- **A0.1** Every write MUST be atomic: write a temporary file in the same
  directory, `fsync()` it, then `rename()` it over the target. A partial write
  to `hcsecd.conf` leaves a daemon that will not start.
- **A0.2** Before the first modification of a file in a given boot, the daemon
  MUST copy the existing file to `<path>.bak`, preserving mode and ownership.
  It MUST NOT overwrite an existing `.bak` on subsequent writes in the same
  boot, so the backup always represents the pre-BluetoothMgr state.
- **A0.3** The daemon MUST NOT perform line-oriented or regex in-place editing
  of any configuration file. It MUST parse the file into a model, modify the
  model, and re-emit the file in full.
- **A0.4** Content the daemon did not author MUST be preserved. This includes
  comments, blank lines, ordering, and entire records for devices BluetoothMgr
  does not manage. "We do not recognise it" is never grounds to drop it.
- **A0.5** The daemon MUST NOT write a file if the re-emitted content is
  byte-identical to what is already on disk. Unnecessary writes cause
  unnecessary reloads, and a reload during pairing is harmful (see A6).
- **A0.6** Temporary files MUST be created with `O_EXCL` and mode `0600`, then
  chmod'ed to the target's mode before the rename.

## A1. `/etc/bluetooth/hcsecd.conf`

Owned by `hcsecd`. Parsed by a lex/yacc grammar
(`usr.sbin/bluetooth/hcsecd/lexer.l`, `parser.y`). Mode `0600`, root only,
because it contains PINs and link keys.

### A1.1 Accepted grammar

```
device {
        bdaddr  xx:xx:xx:xx:xx:xx ;
        name    "string" ;
        key     0x<hex> | nokey ;
        pin     "string" | nopin ;
}
```

Constraints taken directly from the lexer, not from the file's own comments:

- **A1.1.1** `bdaddr` accepts **only** a literal six-octet address matching
  `{hexbyte}:{hexbyte}:{hexbyte}:{hexbyte}:{hexbyte}:{hexbyte}`. It does **not**
  accept an alias from `/etc/bluetooth/hosts`. Note that `bluetooth-config.sh`
  greps for either form; that grep is over-broad and MUST NOT be imitated.
- **A1.1.2** `key` is `0x` followed by hex bytes, or the bare word `nokey`.
- **A1.1.3** `pin` is a double-quoted string, or the bare word `nopin`.
- **A1.1.4** The string token is `\".+\"`, matched greedily on a single line.
  A value containing a double quote or a newline will corrupt the parse of the
  rest of the line. See A7.
- **A1.1.5** Comments run from `#` to end of line.

### A1.2 Semantics the generator MUST respect

- **A1.2.1** The entry with `bdaddr 00:00:00:00:00:00` is the **default entry**.
  `get_key()` falls back to it for any device that has no exact block. The
  daemon MUST NOT remove, reorder relative to nothing, or alter this entry
  unless the user explicitly asks.
- **A1.2.2** Duplicate blocks for the same `bdaddr` are **not** an error to
  `hcsecd`. It keeps the first and discards the rest with a `LOG_ERR`. The
  generator MUST emit at most one block per address. If the parsed input
  contains duplicates, the daemon MUST preserve the first, MUST drop the
  remainder, and SHOULD report this to the client.
- **A1.2.3** The file as shipped contains example blocks named `"Dummy"`
  (`00:01:02:03:04:05`, `00:11:22:33:44:55`). These are base-system boilerplate.
  Per A0.4 they MUST be preserved.
- **A1.2.4** A per-device block MUST exist for every device BluetoothMgr expects
  to keep a link key for. This is not optional. See A6.

### A1.3 Emission

- **A1.3.1** Blocks the daemon did not author MUST be re-emitted verbatim,
  including their original whitespace and trailing comments.
- **A1.3.2** Blocks the daemon authors MUST be emitted in the canonical form
  above, one option per line, tab indented.
- **A1.3.3** The daemon MAY mark its own blocks with a preceding comment line
  `# managed by bluetoothmgr` so a later parse can tell them apart. If it does,
  it MUST tolerate that marker being absent or having been moved by a user.

## A2. `/etc/bluetooth/hosts`

The Bluetooth analogue of `/etc/hosts`. Read by `bt_gethostbyname()` and
`bt_gethostbyaddr()` in `libbluetooth`, which is what `bthost(1)` uses. Mode
`0644`, world readable.

Format, one record per line:

```
BD_ADDR                 Name [ alias0 alias1 ... ]
```

- **A2.1** Fields are whitespace separated. Comments run from `#` to end of
  line.
- **A2.2** An alias MUST match `[A-Za-z0-9._-]+`. Anything else MUST be
  transliterated per A7 before being written.
- **A2.3** **Alias length.** `virtual_oss` opens Bluetooth devices by the path
  `/dev/bluetooth/<name>` and imposes a 32 character limit on it. The prefix
  `/dev/bluetooth/` is 15 characters, and a raw BD_ADDR is 17, giving exactly 32,
  which fails. Therefore the daemon MUST generate aliases of **at most 16
  characters**, giving a maximum path of 31.

  *Caveat: the 32 figure is taken from the observed "Device name too long"
  failure recorded in the audio journey document. The `virtual_oss` source is
  not on this machine, so the exact constant and whether it counts the NUL are
  unverified. 16 is the conservative reading and MUST be treated as the budget
  until someone checks the source.*
- **A2.4** Aliases MUST be unique within the file. On collision the daemon MUST
  append a numeric suffix, truncating the stem as needed to stay within A2.3.
- **A2.5** An alias MUST NOT be a string that `bt_aton()` would parse as an
  address, to avoid ambiguity in `bt_devopen()`, which tries `bt_aton()` first.
- **A2.6** Records for addresses BluetoothMgr does not manage MUST be preserved
  per A0.4.

## A3. `/var/db/hcsecd.keys`

Owned by `hcsecd`. Mode `0600`. Format is one record per line:

```
xx:xx:xx:xx:xx:xx <32 hex characters>
```

- **A3.1** The daemon MUST treat this file as **read-mostly**. `hcsecd` rewrites
  it wholesale on `SIGHUP` and on clean shutdown, so any write by us races with
  that.
- **A3.2** The only mutation the daemon MAY perform is **deleting** a record, as
  the recovery for a stale link key. It MUST do so only while `hcsecd` is
  stopped, or it MUST instead stop `hcsecd`, delete, and start it again.
- **A3.3** The daemon MUST NOT log or transmit key material over IPC. The
  presence or absence of a key is reportable. Its value is not.
- **A3.4** `hcsecd` loads a record from this file only when an exact matching
  `bdaddr` block exists in `hcsecd.conf`. Records without one are dead weight
  and the daemon SHOULD offer to prune them.

## A4. `/var/db/bluetoothmgr/devices.json`

Ours alone. Directory mode `0700`, file mode `0600`, owner root.

- **A4.1** This file MUST NOT contain PINs or link keys. Those live in
  `hcsecd.conf` and `hcsecd.keys`. This is the boring metadata: user-visible
  name, alias, decoded device type, first seen, last connected, auto-connect
  preference.
- **A4.2** The top level MUST be an object with an integer `version` field, so
  the format can migrate.
- **A4.3** A parse failure MUST NOT be fatal. The daemon MUST rename the bad
  file aside, log, and continue with an empty store. The authoritative state
  lives in the kernel and in `hcsecd.conf`; this file is a cache of niceties.

## A5. `/var/run/bluetoothmgr.sock`

- **A5.1** A `SOCK_STREAM` Unix domain socket. The filesystem mode is not the
  authorization boundary; A5.3 is.
- **A5.2** The daemon MUST `unlink()` a stale socket at startup, and MUST remove
  it on clean shutdown.
- **A5.3** Every command MUST be refused unless the peer is root, or the peer
  process belongs to an active GUI session as A9 defines one. This is a desktop
  application, so a peer that is not in a GUI session has no business on this
  socket at all, read-only commands included.

  Several GUI sessions MAY be active at once. A peer in any of them is allowed,
  with no further distinction between users.

  A uid matching a GUI session's user is NOT sufficient. The test is on the
  peer process, per A9.4, so a peer on `ssh` or a text console is refused even
  while that same user is logged into the GUI at that moment.

  Peer uid and pid come from `getsockopt(LOCAL_PEERCRED)`, since `struct xucred`
  carries `cr_pid`. `getpeereid()` reports uid and gid only, so it cannot
  supply the pid A9.4 needs.
- **A5.4** Unsolicited events are subject to A5.3 as well. The daemon MUST NOT
  send the `state` event on accept, nor any broadcast, to a peer A5.3 would
  refuse. An event has no sender, so it is judged on the connecting peer.
- **A5.5** For a command the peer is the process that sent it, not the one that
  connected. The daemon MUST set `LOCAL_CREDS_PERSISTENT` on each accepted
  socket before its first read and take the sender from `sc_pid` of the
  `SCM_CREDS2` message the kernel attaches to every send. A message carrying no
  such credentials MUST authorize nothing. A5.3 and A9.4 apply to that pid.

  A line assembled from sends with differing `sc_pid` MUST close the
  connection: a second sender is splicing into an authorized stream.

## A6. Pairing sequence (the ordering constraint)

This is the single most important rule in Part A. It follows from `hcsecd`
calling `get_key(bdaddr, 1)` with exact matching in its
`Link_Key_Notification` handler, while the PIN and link-key *request* handlers
use `0` and fall back to the default entry. See A3.4.

A device with no block in `hcsecd.conf` will **appear** to pair, because the
default entry answers the PIN request. The resulting link key is then discarded,
and the device must be fully re-paired on every connection.

The daemon MUST perform pairing in exactly this order:

1. Resolve the device name and class. Generate an alias per A2.
2. Write the alias to `/etc/bluetooth/hosts` (A2).
3. Write or update the device's block in `hcsecd.conf`, including the PIN (A1).
4. Reload `hcsecd` (A8.1). Wait for it to complete.
5. **Only now** issue `Create_Connection`, then on `Connection_Complete` issue
   `Authentication_Requested` for that handle (A6.5).
6. On `Link_Key_Notification`, reload `hcsecd` again to force
   `dump_keys_file()` to flush the new key to disk (A8.3).
7. Update `devices.json` (A4).

- **A6.1** The daemon MUST NOT reorder steps 3 and 5. Pairing before the block
  exists loses the key.
- **A6.2** The daemon MUST NOT issue a reload between steps 5 and 6, as that
  drops the in-flight pairing.
- **A6.3** If step 4 fails, the daemon MUST abort and MUST NOT attempt step 5.
- **A6.4** On abort at any step after 2, the daemon SHOULD roll the config back
  to its prior content rather than leaving a half-written block. It SHOULD also
  drop the link step 5 opened, since a failed authentication leaves the ACL
  link up and A6.6 then refuses the retry.
- **A6.5** `Create_Connection` alone is not enough. It leaves an unauthenticated
  ACL link, which exchanges no PIN, so `Link_Key_Notification` never fires and
  the pairing cannot complete. Authentication MUST be requested per link rather
  than by enabling the adapter's global authentication mode, which would change
  behaviour for every device.
- **A6.6** The daemon MUST refuse `pair` for a device that already has a
  connection. `Create_Connection` on an open link produces no
  `Connection_Complete` at all, so step 5 would never report either way.
  Being connected is not being paired; see B5.2.

## A7. Sanitisation of device-supplied strings

Remote device names arrive from untrusted hardware and end up in two files with
strict grammars, plus syslog.

- **A7.1** Before a name is written to `hcsecd.conf` as a quoted string, the
  daemon MUST remove or replace `"`, `\`, newline, and all other control
  characters. A7.1 exists because of A1.1.4.
- **A7.2** Before a name becomes an alias in `/etc/bluetooth/hosts`, it MUST be
  transliterated to `[A-Za-z0-9._-]` with all other bytes replaced by `_`, then
  truncated per A2.3. `bluetooth-config.sh` uses `tr -c '[:alnum:]-,.' _` for
  the same reason. Note that our set excludes `,`, which that script permits.
- **A7.3** The daemon MUST NOT construct any shell command by concatenating a
  device-supplied string. Where it must invoke an external program, such as the
  `service` call in A8.5, it MUST use `posix_spawn()` or `fork()` plus
  `execve()` with an argument vector, never `system()` or `popen()`. A8.1 needs
  no external program at all: it sends a signal.
- **A7.4** A name that sanitises to the empty string MUST fall back to a
  generated alias derived from the address, for example `bt-112233` from the
  last three octets.

## A8. Service control

- **A8.1** To make `hcsecd` re-read its configuration the daemon MUST send it
  `SIGHUP`, which calls `dump_keys_file()`, `read_config_file()` and
  `read_keys_file()` in that order, preserving learned keys. It MUST NOT
  restart the service: a restart tears down the HCI socket and drops in-flight
  pairing.

  The daemon MUST NOT do this by running `service hcsecd reload`. That command
  does not exist. `/etc/rc.d/hcsecd` never sets `extra_commands`, so `reload`
  is not one of its keywords and the call fails with a usage error. There is a
  second, worse reason: for any command that *is* gated by `rcvar`, `rc.subr`
  prints "Cannot ... Set hcsecd_enable to YES" and returns status **0** when
  the service is disabled. A spawned `service` call can therefore report
  success having done nothing, which would let pairing proceed against an
  unreloaded `hcsecd` and lose the link key exactly as F7 does.

  `rc.subr`'s own `reload` is `kill -HUP` on the pid it has found, so
  signalling directly is equivalent and avoids a subprocess entirely.
- **A8.1.1** There is no pidfile to read. `/etc/rc.d/hcsecd` declares
  `pidfile="/var/run/hcsecd.pid"`, but `hcsecd` only calls `daemon(3)` and
  never creates it, so `rc.subr` falls back to matching the process table. The
  daemon MUST do the same: enumerate processes and match on the process name.
- **A8.1.2** A match MUST also require uid 0, because opening the raw HCI
  socket is privileged, so a real `hcsecd` is always root. Matching on the name
  alone would let any user put a program called `hcsecd` in the daemon's way
  and receive a `SIGHUP` from root.
- **A8.1.3** A matched pid MUST be greater than 1, and a zombie MUST NOT count
  as running. `kill(2)` reads 0 as every process in the caller's process group
  and a negative pid as a process group, so a pid that could mean either must
  never reach it: one `SIGHUP` from a root daemon would otherwise become a
  system-wide one. A zombie keeps its name but cannot act on a signal, so
  counting one would park a pairing against a process that has already gone.
- **A8.1.4** More than one matching process MAY exist, for instance a debug
  `hcsecd` started by hand alongside the service. The daemon SHOULD signal all
  of them, as `rc.subr` does, and SHOULD report the count.
- **A8.2** The daemon MUST tolerate `hcsecd` not running. If `hcsecd_enable` is
  not set, pairing cannot persist keys, and the daemon MUST report that as a
  distinct condition rather than failing obscurely. The check is the same
  lookup as A8.1.1 to A8.1.3. An inconclusive answer, such as a process table
  that could not be read, MUST be treated as not running, because that is the
  direction in which nothing is written.
- **A8.3** `hcsecd` flushes keys to disk only on `SIGHUP` and on clean shutdown.
  A `SIGKILL` or a panic loses every key learned since the last flush. The
  daemon SHOULD therefore trigger a reload shortly after a successful pairing,
  per A6 step 6.
- **A8.4** `bthidd` MUST NOT be restarted automatically. Restarting it
  disconnects Bluetooth HID devices, potentially the keyboard the user is
  typing on. Restart MUST be an explicit, confirmed user action.
- **A8.5** `set_power: false` maps to `service bluetooth stop <unit>`, which
  tears down the netgraph stack. This is not equivalent to BlueZ's adapter
  power-off and the UI MUST make the difference visible.

## A9. `/var/run/utx.active`

The utmpx database of current logins, read with `getutxent(3)`. Mode `0644`,
owner `root:wheel`, so only root can write it. Not ours: `login(1)`, `sshd` and
the display manager write it. This file is the input to A5.3.

- **A9.1** GhostBSD writes two records for one graphical login: `lightdm` on
  line `:0`, and the session leader `mate-session` on line `ttyv8` with host
  `:0`.
- **A9.2** A GUI session is a `USER_PROCESS` record whose `ut_line` **or**
  `ut_host` is a display: `:` followed by a decimal display number, optionally
  `.` and a screen number. Both fields are required by A9.1, since matching
  `ut_line` alone misses `mate-session`, which is the record carrying the
  logged-in user.

  A leading `:` alone MUST NOT be accepted: `ut_host` carries the client
  address of an `ssh` login, and `::1` would read as a display. The test MUST
  be bounded by the field size, which carries no terminator when full.
- **A9.3** A text console login, which has no host, is not a GUI session.
  Neither is `ssh` on `pts/N`.
- **A9.4** The peer MUST belong to the session a GUI record names: walking its
  parent chain with `sysctl kern.proc.pid`, either a pid equals the record's
  `ut_pid` or a `ki_sid` does. This is what refuses `ssh` and console peers,
  since a uid test cannot: a user at the GUI who also logs in over `ssh`
  presents the same uid on both.

  The session id is required, not the parent chain alone. A terminal emulator
  or an IDE is reparented to init but keeps the session it was started in,
  while a shell calls `setsid()` and takes its own, so a descent test refuses
  every client launched from a terminal.
- **A9.5** The daemon MUST confirm the session process still exists and runs as
  the peer's uid, so a peer that reached the session tree through `su` or a
  setuid binary is not the GUI user.

  It MUST NOT compare the leader's start time against the record's `ut_tv`:
  `ki_start` is derived from a boot time a suspend re-estimates, so that test
  refuses every session on a machine that has slept. A9.4 and A5.4 carry the
  pid-reuse defence instead.
- **A9.6** If the file is absent, empty or unreadable, the daemon MUST refuse
  every command. A file it cannot read MUST NOT read as no restriction.
- **A9.7** The check MUST run per command, not once on accept. A session can
  end while a client stays connected.

---

# Part B — IPC protocol v0 (provisional)

**Provisional.** The framing, the envelope, and the error model in B1 to B3 are
expected to survive. The device model in B5 and the error vocabulary in B6 will
change once M1 and M2 touch real hardware. This freezes at M2.

## B1. Transport and framing

- **B1.1** `SOCK_STREAM` over the Unix socket at A5.
- **B1.2** Exactly one JSON object per line, terminated by `\n` (0x0A). No
  embedded literal newlines. This makes the protocol debuggable with
  `nc -U /var/run/bluetoothmgr.sock`.
- **B1.3** A line longer than 64 KiB MUST cause the daemon to close the
  connection without parsing it.
- **B1.4** Encoding is UTF-8. Non-UTF-8 bytes in device names MUST be replaced
  before emission, per A7.

## B2. Handshake

On accept, the daemon MUST send exactly one greeting before anything else:

```json
{"event": "hello", "proto": 0, "daemon": "bluetoothmgr/0.1.0"}
```

- **B2.1** A client that does not recognise `proto` MUST disconnect and report a
  version mismatch rather than guessing.
- **B2.2** `proto` is an integer that increments on any breaking change. Until
  1.0 it MAY increment freely.

## B3. Envelope

Client to daemon:

```json
{"id": <int>, "cmd": "<string>", ...}
```

- **B3.1** `id` MUST be present and MUST be unique among the client's in-flight
  requests. The daemon echoes it. Without it a client with two requests
  outstanding cannot match replies.
- **B3.2** The daemon MUST reply to every command exactly once.

Daemon to client, reply:

```json
{"id": <int>, "ok": true,  "result": { ... }}
{"id": <int>, "ok": false, "error": "<code>", "detail": "<human string>"}
```

Daemon to client, unsolicited event, distinguished by having no `id`:

```json
{"event": "<name>", ...}
```

- **B3.3** A message with `id` is a reply. A message with `event` is
  unsolicited. A message MUST NOT carry both.

## B4. Commands

| `cmd` | Fields | Notes |
|---|---|---|
| `get_state` | | Full snapshot, same shape as the `state` event |
| `scan` | `action`: `start`\|`stop`, `duration` | Inquiry. Results arrive as `device_found` events |
| `connect` | `addr` | |
| `disconnect` | `addr` | |
| `pair` | `addr`, `pin` | Executes A6 in full |
| `remove` | `addr` | Drops the `hcsecd.conf` block, the key, and the store entry |
| `set_power` | `on` | See A8.5 |
| `set_discoverable` | `timeout` or `on` | `Write_Scan_Enable`. `timeout` 0 means off. At least one field MUST be present: a request carrying neither is `bad_json`, not "off". `timeout` MUST be 0..3600, checked before the millisecond conversion |
| `set_alias` | `addr`, `alias` | Subject to A2.3 |
| `set_trusted` | `addr`, `trusted` | Store only, no HCI effect |

- **B4.1** Every command MUST be refused per A5.3 with error `not_permitted`.
  There is no unprivileged subset: A5.3 admits only root and a GUI session
  peer, and both may use the whole command set.
- **B4.2** `scan` while a scan is running MUST be idempotent, not an error.
- **B4.3** Several requests MAY be outstanding for the same device. One
  completion event is the answer to all of them, so the daemon MUST fan the
  result out to every waiting request rather than answering the first and
  letting the rest time out.
- **B4.4** `pair`'s `pin` is optional. Absent means the device needs no PIN,
  which `hcsecd` spells `nopin`; an empty string MUST be refused so that there
  is only one spelling for it.
- **B4.5** A `pin` MUST be a JSON string of 1 to 16 bytes. 16 is
  `NG_HCI_PIN_SIZE`, the width of the field in `ng_hci_pin_code_rep_cp`, so a
  longer one could never be sent and MUST be refused rather than truncated.
- **B4.6** A `pin` containing `"`, `\`, a C0 control or DEL MUST be refused.
  Unlike a device name, a PIN is an exact secret, and A7.1 transliteration
  would silently turn it into a different one. The resulting failure would look
  like the device rejecting a correct PIN. The daemon MUST NOT log a PIN, per
  the same reasoning as A3.3.
- **B4.7** While a pairing is parked, between A6 step 5 and step 6, the daemon
  MUST refuse `pair`, `remove`, `set_alias`, `set_trusted` and `set_power` with
  `busy`. The first four reload `hcsecd`, which A6.2 forbids; `set_power` tears
  the stack down per A8.5. `get_state`, `scan`, `connect`, `disconnect` and
  `set_discoverable` MUST remain available.

## B5. State object *(provisional, expect churn)*

```json
{
  "event": "state",
  "adapter_present": true,
  "powered": true,
  "discoverable": false,
  "scanning": false,
  "adapter": {
    "addr": "aa:bb:cc:11:22:03",
    "name": "example-pc",
    "node": "ubt0hci"
  },
  "devices": [
    {
      "addr": "0a:bb:cc:11:22:01",
      "name": "Headset H200",
      "alias": "headphones",
      "type": "headset",
      "class": "28:04:3c",
      "connected": false,
      "paired": true,
      "trusted": true,
      "has_key": true,
      "rssi": null
    }
  ]
}
```

- **B5.1** `addr` is the only stable identity. Everything else MAY change.
- **B5.2** `paired` means a block exists in `hcsecd.conf`. `has_key` means a
  record exists in `hcsecd.keys`. These differ, and the difference is exactly
  the F7 failure mode, so both MUST be reported separately.
- **B5.3** `type` is derived from the class of device major field. The
  vocabulary is provisional: `headset`, `headphones`, `speaker`, `keyboard`,
  `mouse`, `phone`, `computer`, `av`, `unknown`.
- **B5.4** `rssi` is `null` unless the device was seen in the current scan.

## B6. Error codes *(provisional, expect churn)*

| Code | Meaning | Suggested client action |
|---|---|---|
| `not_permitted` | Peer failed the A5.3 check | Report, do not retry |
| `no_adapter` | No HCI node present | Hide the UI |
| `not_found` | Unknown address | Refresh |
| `busy` | Another operation in flight | Retry after the current one |
| `stale_link_key` | Device rejected the stored key | Offer one-click remove key and re-pair |
| `hcsecd_unavailable` | `hcsecd` not running, keys cannot persist | Offer to enable the service |
| `hcsecd_config_error` | Generated config was rejected | Restore `.bak`, report |
| `alias_too_long` | Would exceed A2.3 | Ask for a shorter alias |
| `timeout` | HCI command timed out | Retry once |
| `io_error` | Anything else | Report `detail` |

- **B6.1** `stale_link_key` and `hcsecd_unavailable` exist as distinct codes
  because their recoveries are one-click actions the settings window should
  offer directly, rather than leaving the user to find a forum post.
- **B6.2** `detail` is for humans and MUST NOT be parsed by clients.

## B7. Events

| `event` | When |
|---|---|
| `hello` | Once, on connect (B2) |
| `state` | On connect after `hello`, and whenever anything changes |
| `device_found` | During a scan, per inquiry result |
| `device_added` / `device_removed` | Store changes |
| `pairing_progress` | Stage transitions during A6 |

- **B7.1** The daemon MUST coalesce. It MUST NOT emit a `state` event when
  nothing changed, which is the point of the reconcile timer being a fallback
  rather than the driver.

---

# Part C — Platform constraints (normative)

Properties of FreeBSD's Bluetooth stack, not of BluetoothMgr. They are here
because the design rests on them and the code cites them.

## C1. The privilege boundary is reads versus writes

`ng_btsocket_hci_raw.c` flags a socket `PRIVILEGED` at creation from
`priv_check(td, PRIV_NETBLUETOOTH_RAW)`. An unprivileged socket is then checked
against the static allowlist `ng_btsocket_hci_raw_sec_filter`.

- **C1.1** The allowlist covers every `Read_*` command plus `Inquiry`,
  `Inquiry_Cancel`, `Periodic_Inquiry`, `Remote_Name_Request`,
  `Read_Remote_Features`, `Role_Discovery` and the LE scan commands. Every
  `Write_*`, `Create_Connection`, `Disconnect` and every `SET` ioctl requires
  root. Measured as an ordinary user, `SIOC_HCI_RAW_NODE_SET_DEBUG` is the
  first call to return `EPERM`.
- **C1.2** The filter clears `Return_Link_Keys`, `Link_Key_Notification` and
  `Vendor` for unprivileged sockets, so key material is unreadable without
  root.
- **C1.3** Adapter enumeration, the connection list, name resolution and
  inquiry therefore need no privilege. The daemon holds root only for
  `connect`, `disconnect`, `Write_Scan_Enable` and its config writes, and the
  design MUST NOT foreclose a later split into a root helper plus an
  unprivileged poller.

## C2. HCI events are broadcast

`ng_btsocket_hci_raw_data_input()` walks the socket list and delivers an
`m_dup()` copy of each packet to every socket whose bind address and filter
match. It is a broadcast, not a handoff.

- **C2.1** The daemon MAY watch the same events `hcsecd` sees, including
  `Connection_Complete`, `Disconnection_Complete`, `PIN_Code_Request` and
  `Authentication_Complete`, without disturbing it. Events drive state, so the
  reconcile timer is a fallback and not the primary mechanism.
- **C2.2** The daemon MUST NOT answer a pairing event while `hcsecd` is
  running. Both would send a `PIN_Code_Reply` for the same request and the
  second receives `Command_Disallowed`. Two agents cannot both answer, which is
  why `hcsecd` remains the pairing agent and is driven through its config per
  A1 and A8.

## C3. Hotplug belongs to devd

`/etc/devd/bluetooth.conf` matches USB attach and detach for `ubt[0-9]+` and
runs `service bluetooth quietstart` and `quietstop`.

- **C3.1** The netgraph stack is built before a user could notice, so the
  daemon MUST NOT create nodes. It observes and reports.
- **C3.2** Polling `bt_devenum()` on the reconcile timer is sufficient.
  `/var/run/devd.seqpacket.pipe` would give instant notification and MAY be
  added if the latency matters.

## C4. The `bt_devenum()` callback socket cannot be written to

`bt_devenum()` connects its socket to a dummy node, then re-connects that same
socket to each real node inside the loop. Raw HCI is not `PR_CONNREQUIRED`, so
`soconnectat()` calls `sodisconnect()` first, which sets `SS_CANTSENDMORE`, and
the following `soisconnected()` restores `SS_ISCONNECTED` without clearing it.
The socket is connected and permanently unwritable. Reads and ioctls still
work, which is why it goes unnoticed until the first HCI command.

- **C4.1** Code inside a `bt_devenum()` callback that must send an HCI command
  MUST open its own socket with `bt_devopen()`.
- **C4.2** The daemon MUST install `signal(SIGPIPE, SIG_IGN)` at startup. A
  long-lived root daemon that dies on an unexpected `EPIPE` is unacceptable,
  and this is not the only socket it holds.

This is a defect in the base system rather than in `libbluetooth`'s caller, and
is worth an upstream report.

## C5. Secure Simple Pairing is absent from the base system

- **C5.1** Nothing in the tree implements SSP. `hcsecd` listens for
  `PIN_Code_Request`, `Link_Key_Request` and `Link_Key_Notification` only. The
  kernel files `IO_CAPABILITY_REQUEST` and `SIMPLE_PAIRING_COMPLETE` under
  events needing no post-processing and nothing replies.
  `NG_HCI_IO_CAPABILITY_REQUEST_REPLY` and
  `NG_HCI_USER_CONFIRMATION_REQUEST_REPLY` are `#define`s referenced by no code
  in `sys/`, `lib/` or `usr.sbin/`. Nothing sends
  `Write_Simple_Pairing_Mode`, so the controller falls back to legacy PIN
  pairing.
- **C5.2** Every link key on such a system is therefore a legacy pairing key.
  A report of SSP keys not persisting is describing A3.4, which has a separate
  and concrete cause. The two MUST be kept apart when debugging.
