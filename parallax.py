"""Parallax equivalents of the legacy gateway commands, for new R1s (2027+) and R2s.

Newer vehicles accept only the signed SendParallaxPayload path; older R1s accept the legacy
`sendVehicleCommand`. The Rivian app chooses per command *category* from the vehicle's
SupportedFeatures `PVS_*_CMD` flags (confirmed in the decompiled app, `emm.e0`): if
`PVS_<category>_CMD == "AVAILABLE"` it sends parallax, otherwise legacy. We reproduce that,
reusing the same signed SendParallaxPayload that halloween.py sends — the path issue #4 shows an
R2 actually obeys. (rivian-python-client 2.3.1 added an unsigned `sendVehicleOperation` mutation;
that is a different, unproven path, so we do not use it.)

Operation strings and closure ids come from the app (wsg.java, emm.java) and are confirmed against
rivian-python-client's body.proto. honk/flash/wake have NO parallax equivalent (not mapped in
wsg.java), so they stay legacy-only and may not work on a parallax-only vehicle.
"""
from __future__ import annotations

import struct

from protocol import _varint, f_len, f_var

# command category -> SupportedFeatures flag name (VehicleFeature.java)
CATEGORY_FLAG = {
    "body": "PVS_BD_CMD",
    "security": "PVS_SEC_CMD",
    "comfort": "PVS_COMF_CMD",
    "energy": "PVS_ENRG_CMD",
    "ota": "PVS_OTA_CMD",
}

# ClosureId (body.proto / emm.java): the element(s) in body.closures.open|close
FRUNK, TAILGATE, LIFTGATE = 5, 6, 7
SIDE_BIN_LEFT, SIDE_BIN_RIGHT, CHARGE_PORT = 8, 9, 10
GROUP_WINDOWS = 10000


def _closures(*ids):
    """body.closures.open|close payload: field 1 = packed repeated ClosureId."""
    return f_len(1, b"".join(_varint(i) for i in ids))


def _liftgate(value, model):
    """R1T unlatches the TAILGATE; every other model (and unknown) opens the LIFTGATE.

    The app defaults an unknown model to R1T (TAILGATE); we default to LIFTGATE because the
    parallax-capable models that matter here are the R1S and R2, which both use the liftgate, and
    the model is always known from get_user_information in practice.
    """
    return _closures(TAILGATE if (model or "").upper() == "R1T" else LIFTGATE)


def _temp(value, model):
    """comfort.cabin.set_preconditioning_temperature: field 1 = float32 °C (wire type 5).

    Bounded like the legacy command: 16-29 °C, or the 0/63.5 LO/HI sentinels.
    """
    celsius = float(value)
    if not (16 <= celsius <= 29 or celsius in (0.0, 63.5)):
        raise ValueError("temperature must be 16-29 °C (or 0/63.5 for LO/HI)")
    return b"\x0d" + struct.pack("<f", celsius)


def _charge_limit(value, model):
    """charging.energy.set_charge_limit: field 1 = uint32 state-of-charge percent."""
    percent = int(value)
    if not 50 <= percent <= 100:
        raise ValueError("charge limit must be a percent 50-100")
    return f_var(1, percent)


# comfort.cabin.set_cabin_surface (z22): 1=instance(CabinSurface), 2=level(a32), 3=status(b32),
# 4=device(ConditioningType). All enums; proto3 omits a field left at 0.
CABIN_SURFACE = {  # CabinSurface instance numbers (body/comfort proto, confirmed in w22)
    "steering_wheel": 1, "row1_left": 5, "row1_right": 7,
    "row2_left": 8, "row2_right": 10, "row3_left": 11, "row3_right": 13,
}
HEAT, VENT = 1, 2                 # ConditioningType (v22)
_STATUS_OFF, _STATUS_ON = 1, 2    # b32 on/off status
# legacy level int -> (status, level a32). Seats use 0/2/3/4; the steering wheel uses 0/1/2/3
# (SurfaceHvacStatus.seatCommandValue / steeringWheelCommandValue in the app).
_SEAT_LEVEL = {0: (_STATUS_OFF, 0), 2: (_STATUS_ON, 1), 3: (_STATUS_ON, 2), 4: (_STATUS_ON, 3)}
_WHEEL_LEVEL = {0: (_STATUS_OFF, 0), 1: (_STATUS_ON, 1), 2: (_STATUS_ON, 2), 3: (_STATUS_ON, 3)}


def _surface(instance, device, scale):
    def build(value, model):
        level_int = int(value)
        if level_int not in scale:
            raise ValueError(f"level must be one of {sorted(scale)} for this surface")
        status, level = scale[level_int]
        out = f_var(1, instance)
        if level:
            out += f_var(2, level)
        if status:
            out += f_var(3, status)
        return out + f_var(4, device)
    return build


def _defrost(value, model):
    """comfort.cabin.set_defrost_defog (k22): field 1 = l22 level. The app collapses any
    'on' to DEFOG_DEFROST (3); off is OFF (4)."""
    level = {0: 4, 1: 3}.get(int(value))
    if level is None:
        raise ValueError("defrost level: 0 off, 1 on")
    return f_var(1, level)


# resolved legacy command -> (category, operation, build(value, model) -> payload bytes).
# `value` is the raw CLI value for VALUE_PARAMS commands (else None); `model` is "R1T"/"R1S"/"R2".
COMMANDS = {
    "LOCK_ALL_CLOSURES_FEEDBACK":         ("body", "body.locks.lock",    lambda v, m: b""),
    "UNLOCK_ALL_CLOSURES":                ("body", "body.locks.unlock",  lambda v, m: f_var(1, 1)),
    "OPEN_ALL_WINDOWS":                   ("body", "body.closures.open",  lambda v, m: _closures(GROUP_WINDOWS)),
    "CLOSE_ALL_WINDOWS":                  ("body", "body.closures.close", lambda v, m: _closures(GROUP_WINDOWS)),
    "OPEN_FRUNK":                         ("body", "body.closures.open",  lambda v, m: _closures(FRUNK)),
    "CLOSE_FRUNK":                        ("body", "body.closures.close", lambda v, m: _closures(FRUNK)),
    "OPEN_LIFTGATE_UNLATCH_TAILGATE":     ("body", "body.closures.open",  _liftgate),
    "CLOSE_LIFTGATE":                     ("body", "body.closures.close", _liftgate),
    "OPEN_CHARGE_PORT_DOOR":              ("body", "body.closures.open",  lambda v, m: _closures(CHARGE_PORT)),
    "CLOSE_CHARGE_PORT_DOOR":             ("body", "body.closures.close", lambda v, m: _closures(CHARGE_PORT)),
    "PANIC_ON":                           ("security", "security.alarm.enable_panic",  lambda v, m: b""),
    "PANIC_OFF":                          ("security", "security.alarm.disable_panic", lambda v, m: b""),
    "VEHICLE_CABIN_PRECONDITION_ENABLE":  ("comfort", "comfort.cabin.enable_preconditioning",  lambda v, m: b""),
    "VEHICLE_CABIN_PRECONDITION_DISABLE": ("comfort", "comfort.cabin.disable_preconditioning", lambda v, m: b""),
    "CABIN_PRECONDITIONING_SET_TEMP":     ("comfort", "comfort.cabin.set_preconditioning_temperature", _temp),
    "CABIN_HVAC_LEFT_SEAT_HEAT":          ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row1_left"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_RIGHT_SEAT_HEAT":         ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row1_right"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_REAR_LEFT_SEAT_HEAT":     ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row2_left"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_REAR_RIGHT_SEAT_HEAT":    ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row2_right"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_THIRD_ROW_LEFT_SEAT_HEAT":  ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row3_left"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_THIRD_ROW_RIGHT_SEAT_HEAT": ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row3_right"], HEAT, _SEAT_LEVEL)),
    "CABIN_HVAC_LEFT_SEAT_VENT":          ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row1_left"], VENT, _SEAT_LEVEL)),
    "CABIN_HVAC_RIGHT_SEAT_VENT":         ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["row1_right"], VENT, _SEAT_LEVEL)),
    "CABIN_HVAC_STEERING_HEAT":           ("comfort", "comfort.cabin.set_cabin_surface", _surface(CABIN_SURFACE["steering_wheel"], HEAT, _WHEEL_LEVEL)),
    "CABIN_HVAC_DEFROST_DEFOG":           ("comfort", "comfort.cabin.set_defrost_defog", _defrost),
    "START_CHARGING":                     ("energy",  "charging.energy.start_charging", lambda v, m: b""),
    "STOP_CHARGING":                      ("energy",  "charging.energy.stop_charging",  lambda v, m: b""),
    "CHARGING_LIMITS":                    ("energy",  "charging.energy.set_charge_limit", _charge_limit),
}


def vehicle_info(user, vehicle_id):
    """From a `get_user_information` currentUser payload, the matching vehicle dict (or {})."""
    for vehicle in user.get("vehicles", []):
        if vehicle.get("id") == vehicle_id:
            return vehicle
    return {}


def supported_features(user, vehicle_id):
    """{flag: status} for a vehicle, e.g. {"PVS_BD_CMD": "AVAILABLE", ...}."""
    state = (vehicle_info(user, vehicle_id).get("vehicle") or {}).get("vehicleState") or {}
    return {f.get("name"): f.get("status") for f in (state.get("supportedFeatures") or [])}


def model(user, vehicle_id):
    """The vehicle's model string ("R1T"/"R1S"/"R2"), or None."""
    return (vehicle_info(user, vehicle_id).get("vehicle") or {}).get("model")


def category_available(command, features):
    """Is this command's category flag == AVAILABLE for a vehicle with these features?"""
    entry = COMMANDS.get(command)
    return bool(entry) and features.get(CATEGORY_FLAG[entry[0]]) == "AVAILABLE"


def build(command, value, model):
    """(operation, payload bytes) for a parallax send. KeyError if the command has no equivalent."""
    _category, op, params = COMMANDS[command]
    return op, params(value, model)
