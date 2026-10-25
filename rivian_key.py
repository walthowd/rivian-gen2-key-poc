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
  gearguard on|off      Gear Guard motion cameras (video monitoring)
  alarm on|off          car alarm (panic) — loud!
  stream                watch the Gear Guard live cameras in your browser
  navigate PLACE        send one destination to the vehicle's navigation
  trip PLACE [PLACE…]   plan a trip (with charging stops) and send it to the vehicle;
                        --add adds stops to the active trip, --end stops it
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
import parallax
import trip
import video
from protocol import parse_fields
from common import KEYS_DIR, ROOT, SESSION_FILE, derive_secret, die, key_names, key_path, load_json, load_key, load_session, log, save_json

# Short names for common commands; every rivian-python-client command also works by its
# lowercase name (see `command --list`).
ALIASES = {
    "wake": "WAKE_VEHICLE",
    "honk": "ACTIVATE_EXTERNAL_SOUND",
    "flash": "FLASH_EXTERNAL_LIGHTS",
    "lock": "LOCK_ALL_CLOSURES_FEEDBACK",
    "unlock": "UNLOCK_ALL_CLOSURES",
    "windows_open": "OPEN_ALL_WINDOWS",
    "windows_close": "CLOSE_ALL_WINDOWS",
    "frunk_open": "OPEN_FRUNK",
    "frunk_close": "CLOSE_FRUNK",
    "trunk_open": "OPEN_LIFTGATE_UNLATCH_TAILGATE",
    "trunk_close": "CLOSE_LIFTGATE",
    "liftgate_open": "OPEN_LIFTGATE_UNLATCH_TAILGATE",
    "liftgate_close": "CLOSE_LIFTGATE",
    "charge_port_open": "OPEN_CHARGE_PORT_DOOR",
    "charge_port_close": "CLOSE_CHARGE_PORT_DOOR",
    "panic_on": "PANIC_ON",
    "panic_off": "PANIC_OFF",
    "charge_start": "START_CHARGING",
    "charge_stop": "STOP_CHARGING",
    "precondition_on": "VEHICLE_CABIN_PRECONDITION_ENABLE",
    "precondition_off": "VEHICLE_CABIN_PRECONDITION_DISABLE",
    "precondition_temp": "CABIN_PRECONDITIONING_SET_TEMP",
    "charge_limit": "CHARGING_LIMITS",
}
# Commands seen working on a Gen 2 vehicle with this POC (others are untested here).
TESTED = {"WAKE_VEHICLE", "LOCK_ALL_CLOSURES_FEEDBACK", "UNLOCK_ALL_CLOSURES", "OPEN_ALL_WINDOWS",
          "CLOSE_ALL_WINDOWS", "ACTIVATE_EXTERNAL_SOUND"}
# The Rivian app's honk / flash names (newer rivian-python-client has them too). Gen 2 honks with
# ACTIVATE_EXTERNAL_SOUND. FLASH_EXTERNAL_LIGHTS is accepted by the cloud, but current Gen 2 firmware
# never executes it (it stays at state 3), and the app hides flash on vehicles that don't report the
# HONK_AND_FLASH_COMMAND feature. The combined HONK_AND_FLASH_LIGHTS gets CONFLICT/VEHICLE_COMMAND_ERROR.
EXTRA_COMMANDS = ["ACTIVATE_EXTERNAL_SOUND", "FLASH_EXTERNAL_LIGHTS"]
# Commands that need a value, and the parameter it goes in.
VALUE_PARAMS = {"CABIN_PRECONDITIONING_SET_TEMP": ("HVAC_set_temp", float, "°C 16-29"),
                "CHARGING_LIMITS": ("SOC_limit", int, "percent 50-100")}
# Seat heat/vent take levels 0 off, 2 low, 3 medium, 4 high; the steering wheel takes 0/1/2/3;
# defrost is 0 off / 1 on (these are the values the app's SurfaceHvacStatus maps, legacy and parallax).
for _name in ("LEFT_SEAT_HEAT", "LEFT_SEAT_VENT", "REAR_LEFT_SEAT_HEAT", "REAR_RIGHT_SEAT_HEAT",
              "RIGHT_SEAT_HEAT", "RIGHT_SEAT_VENT", "THIRD_ROW_LEFT_SEAT_HEAT", "THIRD_ROW_RIGHT_SEAT_HEAT"):
    VALUE_PARAMS["CABIN_HVAC_" + _name] = ("level", int, "0 off, 2 low, 3 medium, 4 high")
VALUE_PARAMS["CABIN_HVAC_STEERING_HEAT"] = ("level", int, "0 off, 1 low, 2 medium, 3 high")
VALUE_PARAMS["CABIN_HVAC_DEFROST_DEFOG"] = ("level", int, "0 off, 1 on")


def all_commands():
    from rivian.const import VehicleCommand
    return list(dict.fromkeys([c.value for c in VehicleCommand] + EXTRA_COMMANDS))


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


# getVehicleCommand state codes, as observed on a Gen 2 R1S: 3 = delivered, waiting on the vehicle;
# 0 = the vehicle executed it (honk goes 3 -> 0 with responseCode 928). A command the vehicle doesn't
# support (flash on current firmware) stays at 3.
LEGACY_PENDING_STATE, LEGACY_DONE_STATE = 3, 0
LEGACY_TIMEOUT, LEGACY_POLL_INTERVAL = 20, 2


async def legacy_outcome(api, command_id):
    """Poll a legacy command until the vehicle answers: (answered, state, responseCode)."""
    deadline = time.monotonic() + LEGACY_TIMEOUT
    state = code = None
    while time.monotonic() < deadline:
        await asyncio.sleep(LEGACY_POLL_INTERVAL)
        response = await api.get_vehicle_command_state(command_id)
        data = ((await response.json()).get("data") or {}).get("getVehicleCommand") or {}
        state, code = data.get("state"), data.get("responseCode")
        if state is not None and state != LEGACY_PENDING_STATE:
            return True, state, code
    return False, state, code


async def show_routing(args):
    """Print how each command would be sent for this vehicle (parallax vs legacy)."""
    key = load_key(args.key)
    api = await connect()
    try:
        user = await current_user(api)
        features = parallax.supported_features(user, key["vehicle_id"])
        model = parallax.model(user, key["vehicle_id"])
        print(f"{key.get('vehicle_name') or key['vehicle_id']}  model={model or 'unknown'}")
        if not features:
            print("  vehicle reports no SupportedFeatures — every command goes legacy")
        else:
            print("  category flags (AVAILABLE => that category uses parallax):")
            for category, flag in parallax.CATEGORY_FLAG.items():
                print(f"    {flag:14} {features.get(flag, '(absent)'):16} -> {category}")
        aliases = {v: k for k, v in ALIASES.items()}
        print("  per command:")
        for command in all_commands():
            if command in parallax.COMMANDS:
                route = "PARALLAX" if parallax.category_available(command, features) else "legacy"
            else:
                route = "legacy-only (no parallax equivalent)"
            print(f"    {aliases.get(command, command.lower()):24} {route}")
    finally:
        await api.close()


async def cmd_command(args):
    if getattr(args, "features", False):
        await show_routing(args)
        return
    if args.list or not args.command:
        aliases = {v: k for k, v in ALIASES.items()}
        print("Commands (tested on a Gen 2 vehicle marked *; P = has a parallax equivalent for new R1s/R2s):")
        for command in all_commands():
            value = VALUE_PARAMS.get(command)
            marks = ("*" if command in TESTED else " ") + ("P" if command in parallax.COMMANDS else " ")
            print(f"  {marks} {command.lower():42} "
                  f"{('(' + aliases[command] + ')') if command in aliases else ''}"
                  f"{('  VALUE: ' + value[2]) if value else ''}")
        print("\nRouting for your vehicle: python rivian_key.py command --features")
        print("Halloween: python rivian_key.py halloween --help")
        return
    command = resolve_command(args.command)
    if command in VALUE_PARAMS and args.value is None:
        die(f"{command.lower()} needs a value: {VALUE_PARAMS[command][2]}")
    has_parallax = command in parallax.COMMANDS
    force_parallax, force_legacy = getattr(args, "parallax", False), getattr(args, "legacy", False)
    if force_parallax and not has_parallax:
        die(f"{command.lower()} has no parallax equivalent (honk, flash and wake are legacy-only)")
    key = load_key(args.key)
    api = await connect()
    try:
        user = await current_user(api)
        features = parallax.supported_features(user, key["vehicle_id"])
        model = parallax.model(user, key["vehicle_id"])
        parallax_capable = has_parallax and parallax.category_available(command, features)
        use_parallax = force_parallax or (not force_legacy and parallax_capable)
        if use_parallax:
            secret = derive_secret(key["private_key"], key["vehicle_public_key"])
            log.secret(secret.hex(), "hmac_key")
            op, payload = parallax.build(command, args.value, model)
            log.debug(f"parallax {op} params={payload.hex()} model={model}")
            ok = await halloween.send(api, key, secret, op, payload)
            log(f"{command} (parallax {op}): "
                f"{'accepted' if ok else 'rejected (is the key paired?)'}")
            return ok
        if parallax_capable:
            log("note: sending legacy though the vehicle reports this category as parallax-capable (--parallax to switch)")
        elif not has_parallax and features.get("PVS_BD_CMD") == "AVAILABLE":
            log("note: no parallax equivalent for this command; it may be ignored by a parallax-only vehicle")
        params = None
        if command in VALUE_PARAMS:
            field, kind, _text = VALUE_PARAMS[command]
            params = {field: kind(args.value)}
        command_id = await api.send_vehicle_command(
            command=command, vehicle_id=key["vehicle_id"], phone_id=key["phone_id"],
            identity_id=key["identity_id"], vehicle_key=key["vehicle_public_key"],
            private_key=key["private_key"], params=params)
        log.secret(command_id, "command_id")
        log.debug(f"command {command} params={params}: id={command_id}")
        if not command_id:
            log(f"{command} (legacy): rejected (is the key paired?)")
            return False
        if getattr(args, "no_wait", False):
            log(f"{command} (legacy): accepted (not waiting for the vehicle)")
            return True
        answered, state, code = await legacy_outcome(api, command_id)
        log.debug(f"command {command}: vehicle state={state} responseCode={code}")
        if not answered:
            log(f"{command} (legacy): accepted, but not acknowledged by the vehicle within "
                f"{LEGACY_TIMEOUT}s (it may not support this command)")
            return False
        if state == LEGACY_DONE_STATE:
            log(f"{command} (legacy): completed by the vehicle")
            return True
        log(f"{command} (legacy): not completed by the vehicle (state={state}, responseCode={code})")
        return False
    finally:
        await api.close()


PLACE_RE = re.compile(r"\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*(?:=\s*(.+))?")


def resolve_place(text, saved):
    """A stop from "LAT,LNG[=Name]" or the name of a saved location (Home, Work, favorites)."""
    if match := PLACE_RE.fullmatch(text):
        lat, lng, name = match.groups()
        return {"name": name or f"{lat},{lng}", "latitude": float(lat), "longitude": float(lng)}
    if not text.strip():
        die("empty place name")
    for place in saved:
        kind = {"FAVORITE_HOME": "home", "FAVORITE_WORK": "work"}.get(place.get("locationType"))
        if text.lower() in (kind, (place.get("userGivenName") or "").lower(), (place.get("name") or "").lower()):
            name = place.get("userGivenName") or (text.title() if text.lower() == kind else place["name"])
            coordinate = place.get("coordinate") or {}
            if coordinate.get("latitude") is None or coordinate.get("longitude") is None:
                die(f"{name!r} has no coordinates in your saved locations")
            return {"name": name, "address": place.get("address"), "place_id": place.get("id"),  # a Google place id
                    "latitude": coordinate["latitude"], "longitude": coordinate["longitude"]}
    names = ", ".join(dict.fromkeys(repr(p.get("userGivenName") or p.get("name")) for p in saved)) or "none"
    die(f"{text!r}: not LAT,LNG[=Name] or a saved location (saved: {names})")


async def places(api, user, vehicle, texts):
    saved = [] if all(PLACE_RE.fullmatch(t) for t in texts) else \
        await trip.saved_locations(api, user["id"], vehicle["id"])
    return [resolve_place(text, saved) for text in texts]


async def cmd_navigate(args):
    api = await connect()
    try:
        user = await current_user(api)
        vehicle = pick_vehicle(user, args.vehicle)
        if args.place.startswith(("https://", "http://", "geo:")):  # e.g. a Google Maps share link
            place = {"name": args.place, "url": args.place}
        else:
            [place] = await places(api, user, vehicle, [args.place])
        async with trip.TripWatcher(api, vehicle["id"]) as watch:
            ok = await start_navigation(api, vehicle, place, watch)
        print(f"{place['name']}: {'the vehicle is navigating there' if ok else 'not confirmed by the vehicle'}")
        return ok
    finally:
        await api.close()


async def start_navigation(api, vehicle, place, watch):
    """Share one place with the vehicle and wait until it reports navigating to it. A share that
    reaches the vehicle while it is going to sleep gets lost (the app needs retries too)."""
    before = watch.route
    for attempt in range(1, 4):
        if not await trip.share_location(api, vehicle["id"], place):
            die(f"Rivian refused to send {place['name']!r}")
        print(f"sent {place['name']!r}{f' (try {attempt})' if attempt > 1 else ''}; "
              "waiting for the vehicle to start navigating (wakes it if asleep)…")
        if await watch.wait(lambda route: route and route != before, 60):
            return True
    return False


def trip_summary(plan, stops):
    """Rivian's plan, as a preview (the vehicle plans its own route and charging)."""
    def num(value, scale=1, fmt=".0f"):
        return "?" if value is None else format(value / scale, fmt)
    summary, user_stops = plan.get("summary") or {}, iter(stops)
    print(f"plan: {num(summary.get('totalDriveDistanceMeters'), 1609.344)} mi, "
          f"{num(summary.get('totalTripDurationSeconds'), 3600, '.1f')} h including "
          f"{num(summary.get('totalChargeDurationSeconds'), 60)} min charging, "
          f"arriving with {num(summary.get('arrivalSOCPercent'))}%"
          f"{' (DESTINATION NOT REACHABLE)' if summary.get('destinationReachable') is False else ''}")
    for waypoint in plan.get("waypoints", [])[1:]:
        if waypoint.get("isSystemAdded") and waypoint.get("charger"):
            charger = waypoint["charger"]
            print(f"  charge: {charger.get('name')} ({num(charger.get('chargeDurationSeconds'), 60)} min, "
                  f"arrive {num(waypoint.get('arrivalSOCPercent'))}%)")
        else:
            print(f"  stop:   {next(user_stops, {'name': '?'})['name']} "
                  f"(arrive {num(waypoint.get('arrivalSOCPercent'))}%)")


def insert_position(at, count):
    """Where --add puts new stops among `count` current ones: "next", "end" or stop number N."""
    if at == "next":
        return 0
    if at == "end":
        return count
    if at.isdigit() and 1 <= int(at) <= count + 1:
        return int(at) - 1
    die(f"--at: next, end or a stop number 1-{count + 1}")


async def cmd_trip(args):
    if not args.end and not args.places:
        die("give one or more places (LAT,LNG[=Name] or a saved location), or --end")
    if args.end and args.add:
        die("--add and --end don't go together")
    if args.at and not args.add:
        die("--at only goes with --add")
    if args.at and not (args.at in ("next", "end") or args.at.isdigit()):
        die("--at: next, end or a stop number")
    api = await connect()
    try:
        user = await current_user(api)
        vehicle = pick_vehicle(user, args.vehicle)
        if args.end:
            async with trip.TripWatcher(api, vehicle["id"]) as watch:
                if watch.route == b"":
                    print("the vehicle isn't navigating")
                    return True
                if not await trip.send_trip(api, vehicle["id"], trip.end_trip_message(user["id"])):
                    die("Rivian refused to end the trip")
                ok = await watch.wait(lambda route: route == b"", 90)
            print("trip ended" if ok else "end trip: not confirmed by the vehicle")
            return ok
        stops = await places(api, user, vehicle, args.places)
        if args.add:
            async with trip.TripWatcher(api, vehicle["id"]) as watch:
                current = trip.active_stops(watch.route)
            if watch.route is None:
                die("no trip status from the vehicle — is it online? try again in a minute")
            if not current:
                die("the vehicle isn't navigating — start a trip first (or leave out --add)")
            at = insert_position(args.at or "next", len(current))
            stops = current[:at] + stops + current[at:]
            print("new stops: " + " → ".join(s["name"] for s in stops))
        lat, lng, soc = await trip.vehicle_position(api, vehicle["id"])
        if lat is None or soc is None:
            die("the vehicle hasn't reported its location and charge — wake it and try again")
        status, plans = await trip.plan(api, vehicle["id"], {"latitude": lat, "longitude": lng}, stops,
                                        soc, args.arrive)
        if not plans:
            die(f"Rivian couldn't plan that trip (status {status})")
        trip_summary(plans[0], stops)
        if args.dry_run:
            return True
        # Like the app's trip planner: send the stops, the vehicle plans route and charging itself
        # (it may pick other chargers than the preview above).
        async with trip.TripWatcher(api, vehicle["id"]) as watch:
            ended = bool(watch.route)
            if watch.route:
                # The vehicle merges a trip into the active one (new stops first, then the others), so
                # end that first and send the complete list: the order is then exactly ours.
                print("ending the vehicle's current trip first…")
                if not await trip.send_trip(api, vehicle["id"], trip.end_trip_message(user["id"])) or \
                        not await watch.wait(lambda route: route == b"", 90):
                    die("couldn't end the vehicle's current trip; try `trip --end`, then this again")
            before, ok = watch.route, False
            for attempt in range(1, 4):  # a trip arriving while the vehicle falls asleep is lost
                if not await trip.send_trip_to_vehicle(api, vehicle["id"], {"latitude": lat, "longitude": lng},
                                                       stops, args.arrive):
                    die("Rivian refused the trip")
                print(f"sent{f' (try {attempt})' if attempt > 1 else ''}; waiting for the vehicle to plan it "
                      "(wakes it if asleep)…")
                if ok := await watch.wait(lambda route: route and route != before, 60):
                    await watch.wait(lambda route: False, 15)  # it publishes the charging plan a few seconds later
                    break
        if not ok:
            print("trip not confirmed by the vehicle" +
                  (" (its previous trip was ended); run this again" if ended else ""))
            return False
        print("the vehicle is navigating: " + " → ".join(s["name"] for s in trip.active_stops(watch.route)))
        for name, minutes in trip.active_chargers(watch.route):
            print(f"  charging stop: {name} ({minutes} min)")
        return ok
    finally:
        await api.close()


# Signed parallax operations (like the app's), each confirmed by a state topic the vehicle publishes:
# action -> (operation, topic, done(state bytes) or None for "any change").
SECURITY_OPS = {
    "gearguard": {"on": ("security.video_monitoring.enable_video_monitoring", "security.video_monitoring.state",
                         lambda state: parse_fields(state).get(1) == [2]),
                  "off": ("security.video_monitoring.disable_video_monitoring", "security.video_monitoring.state",
                          lambda state: parse_fields(state).get(1) == [1])},
    "alarm": {"on": ("security.alarm.enable_panic", "security.alarm.state", None),
              "off": ("security.alarm.disable_panic", "security.alarm.state", None)},
}


async def cmd_security(args):
    op, topic, done = SECURITY_OPS[args.cmd][args.action]
    key = load_key(args.key)
    secret = derive_secret(key["private_key"], key["vehicle_public_key"])
    log.secret(secret.hex(), "hmac_key")
    api = await connect()
    try:
        async with trip.TripWatcher(api, key["vehicle_id"], topic) as watch:
            before = watch.route
            if done and before is not None and done(before):
                print(f"{args.cmd} is already {args.action}")
                return True
            if not await halloween.send(api, key, secret, op, b""):
                die(f"Rivian refused {op}")
            print(f"sent {args.cmd} {args.action}; waiting for the vehicle (wakes it if asleep)…")
            ok = await watch.wait(done or (lambda state: state != before), 90)
        log.debug(f"{op}: confirmed={ok} state={(watch.route or b'').hex()}")
        print(f"{args.cmd} {args.action}" + ("" if ok else ": not confirmed by the vehicle (is the key paired?)"))
        return ok
    finally:
        await api.close()


async def cmd_stream(args):
    """Start a Gear Guard live session with our own key and open the camera in a local browser."""
    # Config mode: just play a stream config captured elsewhere (no account/vehicle calls).
    if getattr(args, "config", None):
        import json
        with open(args.config) as handle:
            blob = json.load(handle)
        config = blob.get("gearGuardLiveConfig") or (((blob.get("payload") or {}).get("data") or {})
                                                      .get("gearGuardLiveConfig")) or blob
        if not config.get("endpoint"):
            die("that file has no stream endpoint (expected a gearGuardLiveConfig with an endpoint)")
        print(f"serving captured stream (role {config.get('role')}); opening the viewer.")
        await video.serve(config, open_browser=not args.no_open)
        return True

    key = load_key(args.key)
    secret = derive_secret(key["private_key"], key["vehicle_public_key"])
    log.secret(secret.hex(), "hmac_key")
    vehicle_id = key["vehicle_id"]
    camera = video.CAMERAS[args.camera]
    device_id = video.device_id_for(key, getattr(args, "device_id", None))
    log.secret(device_id, "gearguard_device_id")
    api = await connect()
    config = None
    try:
        # 1. Wake the vehicle and make sure video monitoring is on (the app does this first).
        async with trip.TripWatcher(api, vehicle_id, video.STATE_TOPIC) as monitor:
            if not (monitor.route is not None and video.video_monitoring_on(monitor.route)):
                if not await halloween.send(api, key, secret, video.ENABLE_OP, b""):
                    die("Rivian refused enable_video_monitoring")
                print("waking the vehicle and turning on video monitoring…")
                if not await monitor.wait(video.video_monitoring_on, 90):
                    die("the vehicle didn't confirm video monitoring on (is the key paired?)")
            # 2. Subscribe (commandId = the start's request id) and 3. start. The vehicle serves one
            # session at a time, so a start can be refused while an earlier one (e.g. the app's live
            # view) is still clearing; retry a couple of times before giving up.
            for attempt in range(3):
                request_id, command_id = video.new_request()
                log.debug(f"stream camera={args.camera}({camera}) attempt {attempt + 1} commandId={command_id}")
                print(f"starting the {args.camera} camera stream…"
                      + (f" (retry {attempt})" if attempt else ""))
                async with video.ConfigWatcher(api, vehicle_id, command_id) as watcher:
                    if not await video.send_start(api, key, secret, device_id, camera, request_id):
                        die("Rivian refused start_live_streaming")
                    config = await watcher.wait(40)
                if config:
                    break
                if attempt < 2:
                    print("no stream yet (the vehicle may be finishing another session); waiting…")
                    await asyncio.sleep(20)
        if not config:
            die("no stream config arrived — the vehicle streams one session at a time; close any "
                "live view in the Rivian app, wait a minute, and try again (also needs Park, "
                "Gear Guard on, Connect+, and precise location sharing enabled).")
        log.debug(f"stream config: endpoint host={config['endpoint'].split('/')[2]} "
                  f"role={config.get('role')} ice_servers={len(config.get('iceServers') or [])}")
        print(f"got the stream (role {config.get('role')}); opening the viewer in your browser.")
    finally:
        await api.close()
    # 4. Serve the viewer. Kept separate from the API connection so Ctrl-C only stops the viewer.
    await video.serve(config, open_browser=not args.no_open)


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
    s.add_argument("--features", action="store_true",
                   help="show the vehicle's command routing (parallax vs legacy per command)")
    s.add_argument("--parallax", action="store_true",
                   help="force the parallax path (new R1s/R2s); errors if the command has no equivalent")
    s.add_argument("--legacy", action="store_true", help="force the legacy sendVehicleCommand path")
    s.add_argument("--no-wait", action="store_true",
                   help="legacy only: don't wait for the vehicle to confirm the command")
    s.add_argument("--key", help="key name (only if you have several)")
    s = sub.add_parser("navigate", help="send one destination to the vehicle")
    s.add_argument("place", help='LAT,LNG[=Name] (e.g. "40.76,-91.14=Golf"), a saved location (Home, Work, …) '
                   "or a link (Google Maps share link, geo:LAT,LNG)")
    s.add_argument("--vehicle", help="vehicle name (only if you have several)")
    s = sub.add_parser("trip", help="plan a trip with charging stops and send it to the vehicle")
    s.add_argument("places", nargs="*", help="stops in order: LAT,LNG[=Name] or saved location names")
    s.add_argument("--arrive", type=float, default=20, help="minimum charge %% at the final stop (default 20)")
    s.add_argument("--dry-run", action="store_true", help="plan and show the trip, but don't send it")
    s.add_argument("--add", action="store_true", help="add the places to the trip the vehicle is navigating")
    s.add_argument("--at", help="with --add: next (default), end, or the stop number the new place becomes")
    s.add_argument("--end", action="store_true", help="end the trip running on the vehicle")
    s.add_argument("--vehicle", help="vehicle name (only if you have several)")
    for name, text in (("gearguard", "Gear Guard motion cameras (video monitoring) on/off"),
                       ("alarm", "car alarm (panic) on/off — loud!")):
        s = sub.add_parser(name, help=text)
        s.add_argument("action", choices=["on", "off"])
        s.add_argument("--key", help="key name (only if you have several)")
    s = sub.add_parser("stream", help="start a Gear Guard camera and watch it in your browser")
    s.add_argument("camera", nargs="?", default="front", choices=list(video.CAMERAS),
                   help="which camera to stream (default: front)")
    s.add_argument("--key", help="key name (only if you have several)")
    s.add_argument("--no-open", action="store_true", help="don't open a browser; just print the URL")
    s.add_argument("--device-id", help=argparse.SUPPRESS)  # Gear Guard streaming device id override
    s.add_argument("--config", help=argparse.SUPPRESS)  # serve a stream config captured elsewhere
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
               "remove": cmd_remove, "navigate": cmd_navigate, "trip": cmd_trip,
               "gearguard": cmd_security, "alarm": cmd_security, "stream": cmd_stream}[args.cmd]
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
        return result if args.cmd == "setup" else (1 if result is False else 0)
    if args.cmd == "setup":
        setup_help()  # already names the debug log
        return 1
    print(f"details in {log_path.relative_to(ROOT)} (redacted; attach it when reporting)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
