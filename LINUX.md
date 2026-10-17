# Linux

**A Mac is the easy path.** Linux works too (tested: Debian 13, kernel 6.12, Intel USB adapter),
but it needs root and briefly takes over the Bluetooth adapter.

## Steps

First check Python: `python3 --version` must say **3.11 or newer**. Most current distros qualify
(Debian 12+, Ubuntu 24.04, Fedora, Raspberry Pi OS Bookworm). Ubuntu 22.04 (3.10) and RHEL/Rocky 9
(3.9) need a newer one: `apt install python3.11 python3.11-venv` / `dnf install python3.11`, then use
`python3.11` instead of `python3` below. Or use the Docker route, which brings its own Python.

```bash
git clone https://github.com/walthowd/rivian-gen2-key-poc && cd rivian-gen2-key-poc
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

.venv/bin/python rivian_key.py login
.venv/bin/python rivian_key.py enroll "Linux Key"
sudo .venv/bin/python pair.py            # tells you when to open Set up on the vehicle
.venv/bin/python rivian_key.py status

sudo .venv/bin/python pair.py --restore-adapter   # optional, afterwards: turn adapter privacy back off
```

## What you need

- **Root**, for raw Bluetooth sockets and adapter settings
- **BlueZ** with `bluetoothd` running (and D-Bus)
- A Bluetooth adapter with **LE Secure Connections**, i.e. **Bluetooth 4.2 or newer**. `pair.py` checks this
- The adapter is **`hci0`**
- **Python 3.11+**. glibc and musl distros both work
- **No desktop Bluetooth applet** (GNOME/KDE) acting as the pairing agent while you pair. Close it

## What `pair.py` does to the adapter

1. **Turns on adapter privacy**, if it's off. The vehicle only accepts a pairing that shares
   the computer's identity key (IRK), and Linux only shares it with privacy on. Turning privacy
   on restarts the adapter once, which drops any other Bluetooth connections. Privacy stays on
   afterwards (harmless); `--restore-adapter` turns it off.
2. **Sets bondable and LE Secure Connections on.**
3. **Registers a temporary pairing agent** ("NoInputNoOutput") as BlueZ's default agent. This
   makes the pairing request match what the vehicle expects ("Just Works", like a phone), and
   accepts it. The agent goes away when `pair.py` exits.

It talks to the vehicle over a raw ATT socket because BlueZ (and so bleak) shows no services for
this vehicle: the vehicle refuses BlueZ's Service Changed subscription and BlueZ gives up on the
whole GATT database (see PROTOCOL.md). Pairing happens on that same connection after the handshake.
The bond is kept by BlueZ; remove it with `bluetoothctl remove <address>` if needed.

## Containers

Works (tested on Debian with Docker), as long as the container uses the host's network and the
host's Bluetooth service. Changes still apply to the host's adapter. Run from the repo folder,
after `login` and `enroll`:

```bash
docker run --rm -it --net=host --cap-add NET_ADMIN -v /var/run/dbus:/var/run/dbus \
  -v "$PWD:/app" -w /app python:3.12-slim \
  sh -c "pip install -q -r requirements.txt && python pair.py"
```

- `--net=host`: Bluetooth sockets only work in the host's network namespace
- `--cap-add NET_ADMIN`: to change adapter settings (privacy)
- `-v /var/run/dbus:...`: to use the host's `bluetoothd` (scanning and the pairing agent)

The host still needs BlueZ running. Rootless containers won't work.

## Home Assistant OS

Not supported for pairing. HAOS doesn't give add-ons root on the host, and Home Assistant's own
Bluetooth integration is using the adapter. Pair from a Mac or another Linux machine instead.
If you want HA to use the key, see *Home Assistant users* in the README (`import-ha`).

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `needs root` | run with `sudo .venv/bin/python pair.py` |
| `can't do LE Secure Connections` | adapter is older than Bluetooth 4.2; use a newer USB adapter |
| `no Bluetooth adapter hci0` | adapter missing, or blocked: `rfkill list` / `rfkill unblock bluetooth` |
| `agent: failed to register` | `bluetoothd` not running, or no access to the system D-Bus |
| "Numeric Comparison Failed" / pairing rejected | another agent (desktop applet) answered; close it and retry |
| vehicle disconnects right after "starting SMP" | adapter privacy didn't turn on; check `btmgmt info` shows `privacy` |
| vehicle not found | not in Set up, or Set up timed out (tap Try again) |

Running `sudo btmon` in another terminal shows the pairing exchange in detail. The debug log
in `logs/` has everything else.
