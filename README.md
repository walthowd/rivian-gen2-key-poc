# rivian-gen2-key-poc

Make your **Mac a phone key for a Gen 2 Rivian** (R1S / R1T), so you can send signed commands
(lock, unlock, windows, precondition, …) to it from your own code.

Gen 2 vehicles use a new Bluetooth pairing handshake that existing tools (like the Home
Assistant Rivian integration's **Pair** button) can't do yet
([#181](https://github.com/bretterer/home-assistant-rivian/issues/181)). This proof of concept does it.
How it works is documented in [PROTOCOL.md](PROTOCOL.md).

> **Proof of concept.** Tested on one 2026 R1S. Please [report your results](#report-your-results), good or bad.
> Unofficial; not affiliated with Rivian. Use at your own risk.

## What you need

- A Gen 2 R1S or R1T, and its owner or driver account
- A free **Phone key** slot. Each vehicle allows 4 keys of this type (shown as "Phone key" under
  *Drivers and keys*), shared by all drivers. Digital keys (iPhone / Apple Watch / Android wallet)
  and key cards don't count toward it. `enroll` checks this for you.
- A Mac sitting in or next to the vehicle, with **Python 3.11 or newer**. The `python3` that comes
  with macOS (via Xcode) is 3.9, which is too old. Install a current one with
  [Homebrew](https://brew.sh): `brew install python`

## Steps

**1. Check your Python** (needs 3.11 or newer):

```bash
"$(brew --prefix)/bin/python3" --version
```

If that says 3.11 or higher, continue. If `brew` isn't found or the version is older, install
[Homebrew](https://brew.sh) and run `brew install python`, then check again. (Plain `python3` on a
Mac is usually Apple's 3.9, which is too old.)

**2. Install** (once):

```bash
git clone https://github.com/walthowd/rivian-gen2-key-poc && cd rivian-gen2-key-poc
"$(brew --prefix)/bin/python3" -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Opening a new terminal later? Run `source .venv/bin/activate` in the folder again first.

**3. Sign in and create a key.** The name you pick is what the vehicle will show:

```bash
python rivian_key.py login             # Rivian email, password, verification code
python rivian_key.py enroll "MacBook"  # registers a new phone key called "MacBook"
```

**4. Sit in the vehicle with your Mac and run:**

```bash
python pair.py
```

It tells you what to do on the vehicle's screen:

- Tap **Settings** (the gear icon)

  <img src="docs/step1-settings.jpg" width="360" alt="Settings gear icon">

- Tap **Drivers and keys**

  <img src="docs/step2-drivers-and-keys.jpg" width="360" alt="Drivers and keys">

- Find the phone key with your name (here "POC Mac") and tap **Set up**. Then press Enter on the Mac.

  <img src="docs/step3-set-up.jpg" width="480" alt="Phone key row with Set up button">

- A few seconds later macOS asks to connect. **Click Connect.**

  <img src="docs/macos-connection-request.png" width="480" alt="macOS Connection Request dialog">

- The vehicle confirms:

  <img src="docs/step5-ready.jpg" width="480" alt="Your phone key is ready">

If Set up times out (about a minute), tap **Try again** and run `python pair.py` again.
Pairing this Mac again (e.g. after `remove`)? First forget "Rivian Key …" in System Settings → Bluetooth; `pair.py` warns you if you forgot.
If macOS asks whether your terminal may use Bluetooth, allow it.

**5. Check it and try a command:**

```bash
python rivian_key.py status            # PAIRED (can take a minute to show)
python rivian_key.py command honk
```

## Commands

```bash
python rivian_key.py command --list           # every command; * = seen working on a Gen 2 vehicle
python rivian_key.py command unlock
python rivian_key.py command precondition_temp 21
python rivian_key.py command cabin_hvac_left_seat_heat 3
```

Seen working: `lock`, `unlock`, `windows_open`, `windows_close` (and `wake` is accepted). The
rest come from rivian-python-client and haven't been tried with this POC yet; please report. If the vehicle is asleep, send `wake` first.

### Halloween (Ghostbusters costume)

When the vehicle offers the seasonal Ghostbusters mode:

```bash
python rivian_key.py halloween on                     # / off
python rivian_key.py halloween show ecto1             # ecto1, proton, slimer, trap, random
python rivian_key.py halloween show slimer --motion   # play when someone walks by
python rivian_key.py halloween sound 2                # the 8 sound-effect buttons, 1-8
python rivian_key.py halloween music wraith           # ghostbusters, wraith, spirits, off
python rivian_key.py halloween volume 20
python rivian_key.py halloween lights on              # spooky overhead lights
```

Tested on the vehicle: on/off, the Ecto-1 and Slimer shows, sounds 1 and 2, music (Ghostbusters,
Wraith Hunt, off) and volume. The other shows, sounds and "Spirits" use the same numbering as the
buttons on the vehicle's screen but weren't individually tried; `lights` changes the setting
but had no visible effect while we tested.

To remove the key: `python rivian_key.py remove` (then forget "Rivian Key" in Bluetooth settings).

## Home Assistant users

- **Skip the password:** copy `user_session_token` from the `rivian` entry in HA's
  `/config/.storage/core.config_entries`, then run `python rivian_key.py login --token` and paste it.
- **Experimental: pair HA's own key**, so HA's lock/unlock/climate controls start working.
  Turn on *Vehicle control* in the HA Rivian integration, copy `core.config_entries` to your Mac, then
  `python rivian_key.py import-ha core.config_entries` and `python pair.py`.
  HA registers its key as type "HA", not "phone", and that hasn't been tested yet. Please report what happens.

## Linux

Works too, but needs root and changes Bluetooth adapter settings. See [LINUX.md](LINUX.md).

**Why Linux is harder (a vehicle quirk).** When a computer connects, it normally asks the vehicle
to send "my services changed" alerts. The vehicle refuses that request. Phones and Macs shrug it
off. Linux's Bluetooth system (BlueZ) treats it as fatal and hides all of the vehicle's services,
so normal Bluetooth libraries (including the one Home Assistant uses) see an empty device. To get
around it, the Linux version here talks to the vehicle directly over a raw Bluetooth connection
instead of going through BlueZ. A small fix in BlueZ (ignore that refusal) would remove the need
for this. It is the first known obstacle to pairing straight from Home Assistant (there may be others).

## Report your results

Open an issue with your vehicle (model, year, software version), macOS version, and the log
file from `logs/` that `pair.py` mentions. Logs are detailed but have tokens, keys, IDs, VINs,
names and addresses removed, so they're safe to attach.

## Keep `keys/` private

`keys/` holds your Rivian session and your private key. Anyone with them can command your vehicle.
It's excluded from git. Don't share it.

---

MIT license. Uses [rivian-python-client](https://github.com/bretterer/rivian-python-client).
The protocol was worked out for interoperability, by studying the official Android app, testing
against the vehicle, and an over-the-air capture of the app pairing. No Rivian code is included.
Rivian is a trademark of Rivian Automotive, LLC.
