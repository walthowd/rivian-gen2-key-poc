#!/usr/bin/env python3
"""Pair your key with the vehicle over Bluetooth.

  macOS:  python pair.py
  Linux:  sudo .venv/bin/python pair.py      (see LINUX.md)

It tells you when to open Set Up on the vehicle, then pairs. Check afterwards with
`python rivian_key.py status`.
"""
import sys

if sys.version_info < (3, 11):  # before anything else: dependencies need 3.11+
    sys.exit(f"Python 3.11 or newer is needed (this is {sys.version.split()[0]}). On a Mac: "
             "brew install python, then recreate the venv with \"$(brew --prefix)/bin/python3\" -m venv .venv")

import argparse
import platform
from types import SimpleNamespace
from uuid import UUID

import protocol
from common import ROOT, derive_secret, load_key, log

# Fixed settings (not options, to keep this simple). Change here if you need to.
SETTINGS = dict(
    scan=20,          # seconds to look for the vehicle
    pair_wait=45,     # macOS: seconds to wait for Bluetooth pairing
    hold=3,           # seconds to stay connected afterwards
    attempts=2,       # fresh connections to try
    model=protocol.DEFAULT_MODEL,
)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--key", help="key name (only if you have several)")
    p.add_argument("--restore-adapter", action="store_true", help="Linux only: undo adapter changes and exit")
    cli = p.parse_args(argv)
    args = SimpleNamespace(**SETTINGS, restore_adapter=cli.restore_adapter)

    system = platform.system()
    if system == "Darwin":
        import ble_mac as transport
    elif system == "Linux":
        import ble_linux as transport
    else:
        sys.exit(f"{system} isn't supported — use macOS (or Linux, see LINUX.md)")
    if args.restore_adapter:
        if system != "Linux":
            sys.exit("--restore-adapter is only for Linux")
        transport.restore_adapter_fully(transport.HCI)
        return 0

    key = load_key(cli.key)
    if sys.stdin.isatty():
        shown_as = key.get("device_name") or key["name"]
        print(f"\nOn the vehicle's center screen:\n"
              "  1. tap Settings (the gear icon)\n"
              "  2. tap Drivers and keys\n"
              f"  3. find the phone key named \"{shown_as}\" and tap Set up\n"
              "Set up times out after about a minute; if it does, tap Try again and re-run this.\n")
        input("Press Enter as soon as the Set up screen is showing... ")

    log_path = log.open("pair")
    secret = derive_secret(key["private_key"], key["vehicle_public_key"])
    log.secret(secret.hex(), "hmac_key")
    vas_vehicle_id = str(UUID(key["vas_vehicle_id"]))
    log(f"pairing {key['name']!r} with {key.get('vehicle_name')!r} ({system})")
    log.debug(f"key: source={key.get('source')} device_type={key.get('device_type')} "
              f"created_at={key.get('created_at')}")

    ok = False
    for attempt in range(1, args.attempts + 1):
        if attempt > 1:
            log(f"retrying ({attempt}/{args.attempts})")
        ok = transport.pair(secret, UUID(key["phone_id"]).bytes, UUID(vas_vehicle_id).bytes, vas_vehicle_id, args)
        if ok or ok is None:  # None: retrying can't help
            break
    log(f"{'SUCCESS' if ok else 'FAILED'} — details in {log_path.relative_to(ROOT)} (redacted; attach it when reporting)")
    if ok:
        log("next: python rivian_key.py status")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
