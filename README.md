# BluetoothMgr

Native Bluetooth manager for GhostBSD. C daemon with a MATE panel applet and
standalone settings window. Appears only when a Bluetooth adapter is detected.

> **Status: planning. No implementation yet.**
> The repository currently contains the design documents and the probe programs
> used to verify them. There is nothing to install.

## Why

FreeBSD's Bluetooth stack works, but it has no equivalent of BlueZ's central
object model. Pairing state is spread across `hcsecd.conf`, `/etc/bluetooth/hosts`,
`bthidd.conf` and `/var/db/hcsecd.keys`, with no device database, no event
interface, and a pairing flow that means hand-editing a file with a strict
grammar and poor error messages.

The concrete problem that motivates the project: `hcsecd` discards the link key
for any device that does not already have an exact `bdaddr` block in
`hcsecd.conf`. Its `Link_Key_Notification` handler matches exactly, while the
PIN and link-key *request* handlers fall back to the default entry. So pairing
an unlisted device appears to succeed, then silently fails to persist, and the
device needs full re-pairing on every connection. The only evidence is one line
in syslog.

That is invisible from the command line and it is deterministic, not flaky.
Getting the ordering right automatically is the single most useful thing this
project does. Reproduced on hardware. See `PLAN.md` F7.

## Documents

| File | Contents |
|---|---|
| [`PLAN.md`](PLAN.md) | Research findings, architecture, build order, risks, and a C learning track |
| [`SPEC.md`](SPEC.md) | The contract. Part A (files and ordering) is normative; Part B (IPC) is v0 and provisional |

Read `PLAN.md` sections 1 to 3 first. They are the measured ground truth, and
three of the findings there invalidate assumptions that seem reasonable from
the outside.

## Probes

`tools/probe` holds the three programs used to establish the datapoint behind
the plan. They query the live stack through `libbluetooth` and are the only
runnable thing in the repository today.

```sh
make -C tools/probe
./tools/probe/probe1-enum        # HCI nodes, adapter info, connection list
./tools/probe/probe2-privilege   # unprivileged/root boundary, plus an inquiry
./tools/probe/probe3-adapter     # local name, scan enable, class of device
```

Run them as an ordinary user. All three are expected to work without root. The
one exception is `SIOC_HCI_RAW_NODE_SET_DEBUG` in `probe2`, which must fail with
`EPERM`, because that is the boundary being measured.

If you are reproducing the datapoint on different hardware, the output of these
three is what to compare against `PLAN.md` section 1.

## Target

GhostBSD, and FreeBSD generally. Developed against GhostBSD 26.1
(FreeBSD 15.0-RELEASE-p13, amd64). Requires the Netgraph Bluetooth stack
(`ng_ubt`, `ng_hci`, `ng_bluetooth`, `ng_l2cap`, `ng_btsocket`), which GhostBSD
loads automatically.

## Naming

Matches the existing GhostBSD convention, alongside NetworkMgr.

## License

BSD 3-Clause. See [`LICENSE`](LICENSE).
