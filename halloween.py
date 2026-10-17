"""Halloween "car costume" (Ghostbusters) controls, sent like the Rivian app does.

These go through the `SendParallaxPayload` API (not `sendVehicleCommand`) and must be signed
with a paired key: the cloud accepts unsigned requests, but the vehicle ignores them.
Confirmed on a vehicle: on/off, shows (Ecto-1, Slimer), sounds, music, volume; the remaining
show/sound/track numbers follow the vehicle's button order (see PROTOCOL.md).
"""
import base64
import hashlib
import hmac
import time
import uuid

from protocol import f_len, f_var

PREFIX = "holiday_celebration.car_costume."
GHOSTBUSTERS = 3                     # costume theme
MANUAL, MOTION = 1, 2                # show trigger
SHOWS = {"random": 2, "ecto1": 3, "proton": 4, "slimer": 5, "trap": 6}
TRACKS = {"ghostbusters": 1, "wraith": 2, "spirits": 3}
USAGE = ("on | off | show ecto1|proton|slimer|trap|random [--motion] | sound 1-8 | "
         "music ghostbusters|wraith|spirits|off | volume N | lights on|off")


def operation(action, value=None, motion=False):
    """Map a friendly action to (operation name, protobuf params). Raises ValueError."""
    if action == "on":
        return PREFIX + "set_holiday_celebration_enabled", f_var(1, 1)
    if action == "off":
        return PREFIX + "set_holiday_celebration_enabled", b""
    if action == "show":
        if value not in SHOWS:
            raise ValueError(f"show: one of {', '.join(SHOWS)}")
        settings = f_var(11, SHOWS[value]) + f_var(12, MOTION if motion else MANUAL)
        return PREFIX + "set_car_costume", f_var(1, GHOSTBUSTERS) + f_len(2, settings)
    if action == "sound":
        if not (value or "").isdigit() or not 1 <= int(value) <= 8:
            raise ValueError("sound: a number 1-8 (the 8 sound-effect buttons)")
        return PREFIX + "play_car_costume_effect", f_var(1, int(value))
    if action == "music":
        if value == "off":
            return PREFIX + "update_car_costume_settings", f_var(2, 0)
        if value not in TRACKS:
            raise ValueError(f"music: one of {', '.join(TRACKS)}, off")
        return PREFIX + "update_car_costume_settings", f_var(2, 1) + f_var(3, TRACKS[value])
    if action == "volume":
        if not (value or "").isdigit() or not 0 <= int(value) <= 30:
            raise ValueError("volume: a number 0-30")
        return PREFIX + "update_car_costume_settings", f_var(1, int(value))
    if action == "lights":
        if value not in ("on", "off"):
            raise ValueError("lights: on or off (the spooky overhead lights)")
        return PREFIX + "update_car_costume_settings", f_var(7, 1 if value == "on" else 0)
    raise ValueError(f"unknown action — use: {USAGE}")


def payload(op, params, vehicle_id, identity_id, secret):
    """Signed SendParallaxPayload body (base64), laid out like the Rivian app's.

    command = {1: op, 2: 3, 3: request id, 4: params, 5: timestamp, 7: vehicle id}
    payload = {10: {2: command}, 12: timestamp, 16: request id,
               17: {1: {1: 1 (HMAC-SHA256), 2: HMAC(secret, command)}, 2: identity id}}
    """
    now = time.time()
    stamp = f_var(1, int(now)) + f_var(2, int((now % 1) * 1e9))
    request_id = uuid.uuid4().bytes
    command = (f_len(1, op.encode()) + f_var(2, 3) + f_len(3, request_id) +
               (f_len(4, params) if params else b"") + f_len(5, stamp) + f_len(7, vehicle_id.encode()))
    mac = hmac.new(secret, command, hashlib.sha256).digest()
    signature = f_len(1, f_var(1, 1) + f_len(2, mac)) + f_len(2, identity_id.encode())
    body = f_len(10, f_len(2, command)) + f_len(12, stamp) + f_len(16, request_id) + f_len(17, signature)
    return base64.b64encode(body).decode()


async def send(api, key, secret, op, params):
    """Send via rivian-python-client's GraphQL plumbing. True = accepted by the cloud."""
    from rivian.rivian import BASE_HEADERS, GRAPHQL_GATEWAY  # not exported; POC shortcut
    body = {
        "operationName": "SendParallaxPayload",
        "query": "mutation SendParallaxPayload($payload: String!, $meta: ParallaxMetaInput!) "
                 "{ sendParallaxPayload(payload: $payload, meta: $meta) { __typename success } }",
        "variables": {
            "payload": payload(op, params, key["vehicle_id"], key["identity_id"], secret),
            "meta": {"isVehicleModelOp": True, "model": op, "requiresWakeup": True,
                     "vehicleId": key["vehicle_id"]},
        },
    }
    headers = BASE_HEADERS | {"Csrf-Token": api._csrf_token, "A-Sess": api._app_session_token,
                              "U-Sess": api._user_session_token}
    response = await api._Rivian__graphql_query(headers, GRAPHQL_GATEWAY, body)
    return bool(((await response.json()).get("data") or {}).get("sendParallaxPayload", {}).get("success"))
