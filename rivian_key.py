#!/usr/bin/env python3
"""Rivian account side of the Gen 2 phone-key POC (via rivian-python-client).

  setup                 guided login, enrollment, pairing and command tests (default)
  login                 sign in (email, password, verification code)
  login --token         or paste an existing session token (e.g. from Home Assistant)
  enroll NAME           register a new phone key named NAME for your vehicle
  import-ha FILE        EXPERIMENTAL: use the key Home Assistant already registered
  status                is the key paired with the vehicle?
  command CMD [VALUE]   send a command signed with the key (honk, lock, ...; --list for all)
  halloween ACTION      Ghostbusters costume: on/off, show, sound, music, volume, lights
  remove                unregister the key and delete it locally

With more than one key, pick it with --key NAME.
"""
import sys

if sys.version_info < (3, 11):  # before anything else: dependencies need 3.11+
    sys.exit(f"Python 3.11 or newer is needed (this is {sys.version.split()[0]}). On a Mac: "
             "brew install python, then recreate the venv with \"$(brew --prefix)/bin/python3\" -m venv .venv")

import argparse
import asyncio
import getpass
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from rivian import Rivian
from rivian.exceptions import RivianPhoneLimitReachedError
from rivian.utils import generate_key_pair

import halloween
from common import KEYS_DIR, ROOT, SESSION_FILE, derive_secret, die, key_names, key_path, load_json, load_key, load_session, log, save_json

# Short names for common commands; every rivian-python-client command also works by its
# lowercase name (see `command --list`).
ALIASES = {
    "wake": "WAKE_VEHICLE",
    "honk": "HONK_AND_FLASH_LIGHTS",
    "lock": "LOCK_ALL_CLOSURES_FEEDBACK",
    "unlock": "UNLOCK_ALL_CLOSURES",
    "windows_open": "OPEN_ALL_WINDOWS",
    "windows_close": "CLOSE_ALL_WINDOWS",
    "frunk_open": "OPEN_FRUNK",
    "frunk_close": "CLOSE_FRUNK",
    "precondition_on": "VEHICLE_CABIN_PRECONDITION_ENABLE",
    "precondition_off": "VEHICLE_CABIN_PRECONDITION_DISABLE",
    "precondition_temp": "CABIN_PRECONDITIONING_SET_TEMP",
    "charge_limit": "CHARGING_LIMITS",
}
# Commands seen working on a Gen 2 vehicle with this POC (others are untested here).
TESTED = {"WAKE_VEHICLE", "LOCK_ALL_CLOSURES_FEEDBACK", "UNLOCK_ALL_CLOSURES", "OPEN_ALL_WINDOWS",
          "CLOSE_ALL_WINDOWS"}
# Commands that need a value, and the parameter it goes in.
VALUE_PARAMS = {"CABIN_PRECONDITIONING_SET_TEMP": ("HVAC_set_temp", float, "°C 16-29"),
                "CHARGING_LIMITS": ("SOC_limit", int, "percent 50-100")}
for _name in ("DEFROST_DEFOG", "LEFT_SEAT_HEAT", "LEFT_SEAT_VENT", "REAR_LEFT_SEAT_HEAT", "REAR_RIGHT_SEAT_HEAT",
              "RIGHT_SEAT_HEAT", "RIGHT_SEAT_VENT", "STEERING_HEAT", "THIRD_ROW_LEFT_SEAT_HEAT",
              "THIRD_ROW_RIGHT_SEAT_HEAT"):
    VALUE_PARAMS["CABIN_HVAC_" + _name] = ("level", int, "0 off, 1 on, 2 low, 3 medium, 4 high")


def all_commands():
    from rivian.const import VehicleCommand
    return [c.value for c in VehicleCommand]


def resolve_command(name):
    command = ALIASES.get(name.lower()) or name.upper()
    if command not in all_commands():
        die(f"unknown command {name!r} — see `python rivian_key.py command --list`")
    return command


# ── API helpers ──────────────────────────────────────────────────────
def register_tokens(api):
    for attr in ("_csrf_token", "_app_session_token", "_user_session_token", "_access_token",
                 "_refresh_token", "_otp_token"):
        log.secret(getattr(api, attr, ""), attr.strip("_"))


async def connect():
    api = Rivian(user_session_token=load_session()["user_session_token"])
    await api.create_csrf_token()
    register_tokens(api)
    return api


async def current_user(api):
    response = await api.get_user_information(include_phones=True)
    user = (await response.json())["data"]["currentUser"]
    log.secret(user["id"], "user_id")
    log.debug(f"account: {len(user.get('vehicles', []))} vehicle(s), {len(user.get('enrolledPhones', []))} enrolled phone key(s)")
    for vehicle in user.get("vehicles", []):
        log.secret(vehicle["id"], "vehicle_id")
        log.secret(vehicle.get("vin"), "vin")
        log.secret((vehicle.get("vas") or {}).get("vasVehicleId"), "vas_vehicle_id")
        log.secret(vehicle.get("name"), "vehicle_name", whole_word=True)
        info = vehicle.get("vehicle") or {}
        log.debug(f"vehicle: {info.get('modelYear')} {info.get('model')} "
                  f"ble_key_info={'yes' if (vehicle.get('vas') or {}).get('vasVehicleId') else 'no'}")
    return user


def pick_vehicle(user, wanted):
    vehicles = [v for v in user.get("vehicles", []) if (v.get("vas") or {}).get("vasVehicleId")]
    if wanted:
        vehicles = [v for v in vehicles if wanted in (v.get("name"), v["id"]) or (v.get("vin") or "").endswith(wanted)]
    if len(vehicles) != 1:
        names = ", ".join(repr(v.get("name")) for v in vehicles) or "none"
        die(f"found {len(vehicles)} vehicles ({names}) — pick one with --vehicle NAME")
    return vehicles[0]


def find_phone(user, public_key, vehicle_id):
    for phone in user.get("enrolledPhones", []):
        if (phone.get("vas") or {}).get("publicKey", "").lower() == public_key.lower():
            for enrolled in phone.get("enrolled", []):
                if enrolled.get("vehicleId") == vehicle_id:
                    return phone["vas"]["vasPhoneId"], enrolled
    return None, None


def save_key(name, source, user, vehicle, public_key, private_key, phone_id, enrolled):
    save_json(key_path(name), {
        "name": name,
        "source": source,
        "device_type": enrolled.get("deviceType"),
        "device_name": enrolled.get("deviceName"),
        "user_id": user["id"],
        "vehicle_id": vehicle["id"],
        "vehicle_name": vehicle.get("name"),
        "vas_vehicle_id": str(UUID(vehicle["vas"]["vasVehicleId"])),
        "vehicle_public_key": vehicle["vas"]["vehiclePublicKey"],
        "public_key": public_key,
        "private_key": private_key,
        "phone_id": phone_id,
        "identity_id": enrolled.get("identityId"),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


def save_session(token):
    log.secret(token, "session_token")
    save_json(SESSION_FILE, {"user_session_token": token})
    log("signed in (session saved in keys/ — keep it private)")


def next_step(name, shown_as):
    key_arg = f' --key "{name}"' if len(key_names()) > 1 else ""
    log("next: take this computer to the vehicle (sit inside, or right next to it), then run:")
    log(f"      python pair.py{key_arg}")
    log(f"      it tells you when to open Set up for '{shown_as}' on the vehicle's screen")


# ── commands ─────────────────────────────────────────────────────────
def after_login():
    names = key_names()
    if names:
        log(f"next: python rivian_key.py status   (your keys: {', '.join(names)})")
    else:
        log('next: python rivian_key.py enroll "MacBook"   (any name you like; the vehicle shows it)')


async def cmd_login(args):
    if args.token:
        save_session(getpass.getpass("Session token (input hidden): ").strip())
        if not getattr(args, "guided", False):
            after_login()
        return
    email = input("Rivian email: ").strip()
    password = getpass.getpass("Rivian password: ")
    api = Rivian()
    try:
        await api.create_csrf_token()
        register_tokens(api)
        await api.authenticate(email, password)
        register_tokens(api)
        log.debug(f"sign-in: verification code required={getattr(api, '_otp_needed', False)}")
        if getattr(api, "_otp_needed", False):
            await api.validate_otp(email, input("Verification code from Rivian: ").strip())
        register_tokens(api)
        token = getattr(api, "_user_session_token", "")
        if not token:
            die("sign-in did not return a session")
        save_session(token)
        if not getattr(args, "guided", False):
            after_login()
    finally:
        await api.close()


async def free_phone_slots(api, vehicle_id):
    """(free, max) Phone key slots on the vehicle, or None if Rivian doesn't say."""
    from rivian.rivian import BASE_HEADERS, GRAPHQL_GATEWAY  # not exported; POC shortcut
    body = {"operationName": "DeviceSlots", "variables": None,
            "query": "query DeviceSlots { currentUser { vehicles { id vehicle { deviceSlots "
                     "{ phone { max free } } } } } }"}
    headers = BASE_HEADERS | {"A-Sess": api._app_session_token, "U-Sess": api._user_session_token}
    try:
        response = await api._Rivian__graphql_query(headers, GRAPHQL_GATEWAY, body)
        for vehicle in (await response.json())["data"]["currentUser"]["vehicles"]:
            if vehicle["id"] == vehicle_id:
                slots = vehicle["vehicle"]["deviceSlots"]["phone"]
                return slots["free"], slots["max"]
    except Exception as error:  # noqa: BLE001 — informational only
        log.debug(f"device slots unavailable: {type(error).__name__}")
    return None


SLOTS_FULL = ("no free Phone key slots on this vehicle ({used} of {max} used). Phone keys are shared by "
              "all drivers; Digital keys (iPhone/Watch wallet) and key cards don't count. Delete an "
              "unused Phone key in the Rivian app (or `rivian_key.py remove`) and try again")


async def cmd_enroll(args):
    log.secret(args.name, "key_name", whole_word=True)
    if not re.fullmatch(r"[A-Za-z0-9 ._-]{1,32}", args.name):
        die("NAME: up to 32 letters, digits, spaces, . _ -")
    if key_path(args.name).exists():
        die(f"you already have a key named {args.name!r}")
    api = await connect()
    try:
        user = await current_user(api)
        vehicle = pick_vehicle(user, args.vehicle)
        slots = await free_phone_slots(api, vehicle["id"])
        if slots:
            free, total = slots
            log(f"Phone key slots free on {vehicle.get('name')!r}: {free} of {total}")
            if free < 1:
                die(SLOTS_FULL.format(used=total - free, max=total))
        public_key, private_key = generate_key_pair()
        log(f"registering phone key {args.name!r} for {vehicle.get('name')!r}")
        try:
            enrolled_ok = await api.enroll_phone(user_id=user["id"], vehicle_id=vehicle["id"], device_type="phone",
                                                 device_name=args.name, public_key=public_key)
        except RivianPhoneLimitReachedError:
            die(SLOTS_FULL.format(used="all", max=(slots or (0, 4))[1]))
        if not enrolled_ok:
            die("Rivian refused the enrollment")
        phone_id, enrolled = find_phone(await current_user(api), public_key, vehicle["id"])
        for _ in range(12):  # Rivian can take a little while to list a new key
            if phone_id:
                break
            await asyncio.sleep(5)
            phone_id, enrolled = find_phone(await current_user(api), public_key, vehicle["id"])
        if not phone_id:
            die("registered, but the key isn't visible yet — try `status` in a minute")
        save_key(args.name, "enroll", user, vehicle, public_key, private_key, phone_id, enrolled)
        if not getattr(args, "guided", False):
            next_step(args.name, args.name)
    finally:
        await api.close()


def ha_rivian_entries(data):
    """Accept a whole core.config_entries file, its entries list, or a single entry."""
    if isinstance(data, dict) and isinstance(data.get("data"), dict) and "entries" in data["data"]:
        data = data["data"]["entries"]
    if isinstance(data, dict):
        data = [data]
    return [entry for entry in data if isinstance(entry, dict) and entry.get("domain") == "rivian"]


async def cmd_import_ha(args):
    entries = ha_rivian_entries(load_json(args.file))
    if len(entries) != 1:
        die(f"expected one Home Assistant 'rivian' entry in that file, found {len(entries)}")
    token = (entries[0].get("data") or {}).get("user_session_token")
    options = entries[0].get("options") or {}
    public_key, private_key = options.get("public_key"), options.get("private_key")
    if not token:
        die("that entry has no session token")
    if not (public_key and private_key):
        die("that entry has no key — turn on 'Vehicle control' in the HA Rivian integration first")
    log.secret(private_key, "private_key")
    log.secret(public_key, "public_key")
    save_session(token)
    api = await connect()
    try:
        user = await current_user(api)
        vehicle = pick_vehicle(user, args.vehicle)
        phone_id, enrolled = find_phone(user, public_key, vehicle["id"])
        if not phone_id:
            die("Home Assistant's key isn't registered for this vehicle — turn on 'Vehicle control' for it")
        shown_as = enrolled.get("deviceName") or "Home Assistant"
        name = "ha-" + re.sub(r"[^A-Za-z0-9._-]+", "-", shown_as).strip("-")
        log.secret(shown_as, "key_name", whole_word=True)
        log.secret(name, "key_name", whole_word=True)
        if key_path(name).exists():
            die(f"already imported as {name!r} — `remove` is not for HA keys; delete keys/{name}.json to re-import")
        save_key(name, "import-ha", user, vehicle, public_key, private_key, phone_id, enrolled)
        log(f"imported Home Assistant's key as {name!r}")
        log("EXPERIMENTAL: proven only for phone keys; HA registers type 'HA'. Please report what happens.")
        next_step(name, shown_as)
    finally:
        await api.close()


async def cmd_status(args):
    key = load_key(args.key)
    api = await connect()
    try:
        response = await api.get_drivers_and_keys(key["vehicle_id"])
        for user in (await response.json())["data"]["getVehicle"].get("invitedUsers", []):
            for device in user.get("devices") or []:
                if device.get("id") == key["phone_id"]:
                    log.debug(f"device: type={device.get('type')} paired={device.get('isPaired')} "
                              f"enabled={device.get('isEnabled')}")
                    if getattr(args, "guided", False):  # setup reports progress itself
                        return device
                    paired = device.get("isPaired")
                    log(f"{key['name']}: {'PAIRED' if paired else 'not paired yet'} "
                        f"(isPaired={paired}, isEnabled={device.get('isEnabled')})")
                    if not paired:
                        log("just ran pair.py? the vehicle reports pairing to Rivian within a minute or so — check again")
                    return device
        if not getattr(args, "guided", False):
            log(f"{key['name']}: not registered on the vehicle any more")
    finally:
        await api.close()


async def cmd_command(args):
    if args.list or not args.command:
        aliases = {v: k for k, v in ALIASES.items()}
        print("Commands (tested on a Gen 2 vehicle marked *):")
        for command in all_commands():
            value = VALUE_PARAMS.get(command)
            print(f"  {'*' if command in TESTED else ' '} {command.lower():42} "
                  f"{('(' + aliases[command] + ')') if command in aliases else ''}"
                  f"{('  VALUE: ' + value[2]) if value else ''}")
        print("\nHalloween: python rivian_key.py halloween --help")
        return
    command = resolve_command(args.command)
    params = None
    if command in VALUE_PARAMS:
        field, kind, text = VALUE_PARAMS[command]
        if args.value is None:
            die(f"{command.lower()} needs a value: {text}")
        params = {field: kind(args.value)}
    key = load_key(args.key)
    api = await connect()
    try:
        command_id = await api.send_vehicle_command(
            command=command, vehicle_id=key["vehicle_id"], phone_id=key["phone_id"],
            identity_id=key["identity_id"], vehicle_key=key["vehicle_public_key"],
            private_key=key["private_key"], params=params)
        log.secret(command_id, "command_id")
        log.debug(f"command {command} params={params}: id={command_id}")
        log(f"{command}: {'accepted' if command_id else 'rejected (is the key paired?)'}")
        return bool(command_id)
    finally:
        await api.close()


async def cmd_halloween(args):
    try:
        op, params = halloween.operation(args.action, args.value, args.motion)
    except ValueError as error:
        die(str(error))
    key = load_key(args.key)
    secret = derive_secret(key["private_key"], key["vehicle_public_key"])
    log.secret(secret.hex(), "hmac_key")
    api = await connect()
    try:
        ok = await halloween.send(api, key, secret, op, params)
        log.debug(f"halloween {op} params={params.hex()}: accepted={ok}")
        log(f"halloween {args.action} {args.value or ''}".strip() +
            (": sent" if ok else ": rejected (is the key paired?)"))
    finally:
        await api.close()


async def cmd_remove(args):
    key = load_key(args.key)
    if key.get("source") == "import-ha":
        die("this is Home Assistant's key — turn off 'Vehicle control' in HA instead")
    if input(f"Unregister {key['name']!r} from {key.get('vehicle_name')!r} and delete it? [y/N] ").lower() != "y":
        return
    api = await connect()
    try:
        if not await api.disenroll_phone(identity_id=key["identity_id"]):
            die("Rivian refused to remove the key")
        key_path(key["name"]).unlink()
        log("removed — also forget the vehicle in your computer's Bluetooth settings")
    finally:
        await api.close()


def error_text(error):
    """One safe line about an exception: plain text/number arguments plus any GraphQL error
    codes. Never the exception itself — Rivian API errors carry the whole response (other
    drivers' names, IDs)."""
    parts = [str(a) for a in error.args if isinstance(a, (str, int))]
    for arg in error.args:
        for item in (arg.get("errors") or []) if isinstance(arg, dict) else []:
            extensions = item.get("extensions") or {}
            parts.append("/".join(str(v) for v in (extensions.get("code"), extensions.get("reason")) if v)
                         or "no error code")
            log.debug(f"graphql error message: {item.get('message')}")
    return f"{type(error).__name__}: {' '.join(parts)}"[:300]


ISSUES_URL = "https://github.com/walthowd/rivian-gen2-key-poc/issues/new"


def setup_help():
    if log.file:
        log(f"Setup debug log: {Path(log.file.name).relative_to(ROOT)} (redacted)")
    log("Also attach the logs/pair-*.log file printed by pairing, if attempted. Keep keys/ private.")
    log(f"Report an issue with those logs and your vehicle/OS versions: {ISSUES_URL}")


def choose_key(names):
    if len(names) == 1:
        return names[0]
    print("Choose an existing key:")
    for index, name in enumerate(names, 1):
        print(f"  {index}. {name}")
    while True:
        choice = input("Key number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        print("Enter one of the key numbers above.")


def key_ready(device):
    return bool(device and device.get("isPaired") and device.get("isEnabled"))


async def wait_for_status(args, done, message, attempts=6):
    """Re-check status every 10s until done(device), saying `message` once while waiting."""
    device = await cmd_status(args)
    for attempt in range(attempts):
        if done(device):
            break
        if attempt == 0:
            log(message)
        await asyncio.sleep(10)
        device = await cmd_status(args)
    return device


async def test_commands(key_name):
    commands = ("wake", "lock", "unlock", "windows_open", "windows_close", "honk")
    print("\nOptional vehicle tests: selecting a command sends it to the vehicle.")
    while True:
        for index, command in enumerate(commands, 1):
            print(f"  {index}. {command}")
        print("  0. Finish")
        choice = input("Test command [0]: ").strip() or "0"
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(commands):
            print("Enter a command number, or 0 to finish.")
            continue
        try:
            accepted = await cmd_command(SimpleNamespace(
                key=key_name, command=commands[int(choice) - 1], value=None, list=False))
        except Exception as error:  # noqa: BLE001 — one failed test shouldn't end setup
            log.exception(f"{commands[int(choice) - 1]}: error: {error_text(error)}")
            accepted = False
        if not accepted:
            setup_help()


async def cmd_setup(args):
    if not sys.stdin.isatty():
        die("guided setup needs an interactive terminal; use login, enroll, status or command individually")
    if not SESSION_FILE.exists() or not load_session().get("user_session_token"):
        await cmd_login(SimpleNamespace(token=args.token, guided=True))
    else:
        log("using saved sign-in")

    args.guided = True
    names = key_names()
    if args.key:
        args.key = load_key(args.key)["name"]
    elif names:
        args.key = choose_key(names)
    if args.key:
        device = await cmd_status(args)
        if device is None:
            # Removed on the vehicle or in the app: its local file is useless now. Keep it aside
            # (not deleted) and set up a fresh key in its place.
            stale = key_path(args.key)
            stale.rename(stale.with_name(stale.name + ".unregistered"))
            log(f"{args.key}: no longer registered with the vehicle — setting up a new key "
                f"(old file kept as keys/{stale.name}.unregistered)")
    if not args.key or device is None:
        default = args.key or "MacBook"
        name = input(f"Name for the new phone key [{default}]: ").strip() or default
        await cmd_enroll(SimpleNamespace(name=name, vehicle=args.vehicle, guided=True))
        args.key = name
        device = await wait_for_status(args, lambda d: d is not None,
                                       "waiting for the vehicle to list the new key…")
    if device is None:
        log("Setup cannot continue: the new key isn't listed on the vehicle yet. "
            "Wait a minute and run setup again.")
        setup_help()
        return 1
    log(f"{args.key}: {'paired' if device.get('isPaired') else 'registered, not paired yet'}"
        f"{'' if device.get('isEnabled') else ' (disabled)'}")
    if not device.get("isPaired"):
        print("\nPairing requires you to be inside the vehicle with this computer. "
              "You will also need to use the vehicle's center screen.")
        if input("Start Bluetooth pairing now? [y/N] ").strip().lower() not in ("y", "yes"):
            log("Setup saved. Run python rivian_key.py again when you are in the vehicle.")
            return 0
        pair_cmd = [sys.executable, str(ROOT / "pair.py"), "--key", args.key]
        if platform.system() == "Linux" and os.geteuid() != 0:
            pair_cmd.insert(0, "sudo")  # raw Bluetooth sockets; see LINUX.md
        while True:
            result = subprocess.run(pair_cmd, check=False)
            log.debug(f"pair.py exited with status {result.returncode}")
            if result.returncode == 0:
                device = await wait_for_status(args, lambda d: key_ready(d) or d is None,
                                               "waiting for the vehicle to confirm pairing to Rivian…")
            else:
                device = await cmd_status(args)
            if key_ready(device):
                break
            setup_help()
            if result.returncode == 0 or input(
                    "After following the pairing advice, try pairing again? [y/N] "
                    ).strip().lower() not in ("y", "yes"):
                break

    if not key_ready(device):
        log("Setup not confirmed: the key must be both paired and enabled. "
            "If pairing just succeeded, wait a minute and run setup again; "
            "if disabled, check Drivers and keys on the vehicle.")
        setup_help()
        return 1
    log("SUCCESS — your key is paired and enabled.")
    await test_commands(args.key)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", metavar="COMMAND")
    s = sub.add_parser("setup", help="guided setup (also runs when no command is given)")
    s.add_argument("--key", help="existing key to use")
    s.add_argument("--vehicle", help="vehicle name (only if you have several)")
    s.add_argument("--token", action="store_true", help="use a session token when signing in")
    sub.add_parser("login", help="sign in").add_argument(
        "--token", action="store_true", help="paste an existing session token instead (prompted, not echoed)")
    s = sub.add_parser("enroll", help="register a new phone key")
    s.add_argument("name", help="name shown on the vehicle, e.g. 'MacBook'")
    s.add_argument("--vehicle", help="vehicle name (only if you have several)")
    s = sub.add_parser("import-ha", help="EXPERIMENTAL: use Home Assistant's key")
    s.add_argument("file", help="HA's .storage/core.config_entries (or just its rivian entry)")
    s.add_argument("--vehicle", help="vehicle name (only if you have several)")
    for name, text in (("status", "is the key paired?"), ("remove", "unregister and delete the key")):
        sub.add_parser(name, help=text).add_argument("--key", help="key name (only if you have several)")
    s = sub.add_parser("command", help="send a signed command (see --list)")
    s.add_argument("command", nargs="?", help="e.g. honk, lock, seat_heat... (--list shows all)")
    s.add_argument("value", nargs="?", help="for commands that need one (temperature, level, limit)")
    s.add_argument("--list", action="store_true", help="list every command")
    s.add_argument("--key", help="key name (only if you have several)")
    s = sub.add_parser("halloween", help="Ghostbusters car costume: " + halloween.USAGE)
    s.add_argument("action", choices=["on", "off", "show", "sound", "music", "volume", "lights"])
    s.add_argument("value", nargs="?", help="show name, sound 1-8, track/off, volume, on/off")
    s.add_argument("--motion", action="store_true", help="show: play on motion instead of now")
    s.add_argument("--key", help="key name (only if you have several)")
    args = p.parse_args(argv)
    if args.cmd is None:
        args = p.parse_args(["setup"])

    KEYS_DIR.mkdir(mode=0o700, exist_ok=True)
    log_path = log.open(f"rivian_key-{args.cmd}")
    handler = {"setup": cmd_setup, "login": cmd_login, "enroll": cmd_enroll, "import-ha": cmd_import_ha,
               "status": cmd_status, "command": cmd_command, "halloween": cmd_halloween,
               "remove": cmd_remove}[args.cmd]
    try:
        result = asyncio.run(handler(args))
    except (KeyboardInterrupt, EOFError):
        log("Stopped. Your saved sign-in and keys are kept; run setup again to continue.")
        return 130
    except SystemExit as error:
        if args.cmd != "setup":
            raise
        setup_help()
        return error.code or 0
    except KeyError as error:
        log.exception(f"unexpected reply from Rivian (missing {error}) — session expired? run `login` again")
    except Exception as error:  # noqa: BLE001 — rivian-python-client raises many types
        log.exception(f"error: {error_text(error)}")
    else:
        return result if args.cmd == "setup" else 0
    if args.cmd == "setup":
        setup_help()  # already names the debug log
        return 1
    print(f"details in {log_path.relative_to(ROOT)} (redacted; attach it when reporting)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
