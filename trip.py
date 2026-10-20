"""Navigation: send a destination or a planned trip to the vehicle, like the Rivian app does.

Two ways, both seen in the app's traffic (no paired key needed, only a signed-in session):
- ParseAndShareLocationToVehicle: "send to vehicle" for one place (a telenav.id link).
- PlanTrip2 then SendUpdatedTrip: a full trip with legs and charging stops, sent as a
  SendParallaxPayload with model c2v_navigation.trip_copilot.updated_trip (unsigned). An
  "end_trip_<ms>" trip with no legs ends navigation on the vehicle.
"""
import base64
import struct
import time
import uuid
from urllib.parse import urlencode

from protocol import f_len, f_var

TRIP_MODEL = "c2v_navigation.trip_copilot.updated_trip"
# What the app sent: charging networks it plans with, and the matching filter switches.
NETWORKS = ("10001", "10025", "10027", "10030", "10031", "10056", "10050")
SWITCHES = ("switchExcludeMotorway:false", "switchExcludeFerry:false", "switchExcludeToll:false")
FILTERS = ("switchAvoidAdapterRequired:false", "switchRivianFilter:true", "switchChargePointFilter:false",
           "switchElectrifyAmericaFilter:false", "switchEVConnectFilter:false", "switchEVgoFilter:false",
           "switchIONNAFilter:true", "switchTeslaFilter:true")

PLAN_QUERY = (
    "query PlanTrip2($waypoints: [RequestWaypointInput!]!, $vehicle: String!, $startingSoc: Float, "
    "$startingRangeMeters: Float, $targetArrivalSocPercent: Float, $driveMode: DriveMode, "
    "$networkPreferences: [NetworkPreference!], $hasAdapter: Boolean, $routePreferences: RoutePreferences, "
    "$departureTime: UnixTimestamp) { planTrip2(waypoints: $waypoints vehicle: $vehicle "
    "startingSoc: $startingSoc startingRangeMeters: $startingRangeMeters "
    "targetArrivalSocPercent: $targetArrivalSocPercent driveMode: $driveMode "
    "networkPreferences: $networkPreferences hasAdapter: $hasAdapter routePreferences: $routePreferences "
    "departureTime: $departureTime) { plans { planIdentifierMetadata { abrpRouteId legs { abrpLegId "
    "routeRequest } } summary { arrivalSOCPercent destinationReachable totalChargeDurationSeconds "
    "totalDriveDistanceMeters totalTripDurationSeconds } waypoints { arrivalSOCPercent arrivalTimeUTC "
    "charger { chargeDurationSeconds entityId name } isSystemAdded latitude longitude waypointType } } "
    "status } }")


def f_double(field, value):  # fields 1-15 only
    return bytes([(field << 3) | 1]) + struct.pack("<d", value)


def f_float(field, value):  # fields 1-15 only
    return bytes([(field << 3) | 5]) + struct.pack("<f", value)


def share_url(stop):
    """What ParseAndShareLocationToVehicle gets: a link given as-is, the app's telenav.id link for a
    place with a Google place id (Rivian errors on telenav links without one), else a Google Maps link."""
    if stop.get("url"):
        return stop["url"]
    coords = f"{stop['latitude']},{stop['longitude']}"
    if not stop.get("place_id"):
        return "https://www.google.com/maps/search/?" + urlencode({"api": 1, "query": coords})
    query = {"geo_coordinates": coords, "entity_id": stop.get("place_id") or "", "name": stop["name"],
             "nav_coordinates": coords, "address": stop.get("address") or "", "source_type": "telenav"}
    return "https://telenav.id/entity?" + urlencode({k: v for k, v in query.items() if v})


def plan_variables(vehicle_id, origin, stops, soc, target_soc):
    def waypoint(stop, **extra):
        return {**extra, "entityId": stop.get("place_id") or "", "latitude": stop["latitude"],
                "longitude": stop["longitude"], "waypointType": "OTHER"}
    return {
        "departureTime": str(int(time.time() * 1000)), "driveMode": "EVERYDAY", "hasAdapter": True,
        "networkPreferences": [{"networkId": n, "preference": 1} for n in NETWORKS],
        "routePreferences": {"avoidFerries": False, "avoidHighways": False, "avoidTolls": False},
        "startingRangeMeters": 0, "startingSoc": soc, "targetArrivalSocPercent": target_soc,
        "vehicle": vehicle_id,
        "waypoints": [waypoint(origin, bearingDegrees=0)] + [waypoint(s) for s in stops],
    }


def _destination(waypoint, stop):
    """A leg's end: a charger the planner added, or one of the user's stops."""
    charger = waypoint.get("charger")
    if waypoint.get("isSystemAdded") and charger:
        name, place_id, flags = charger["name"], charger["entityId"], f_var(4, 1) + f_var(5, 1)
    else:
        name, place_id, flags = stop["name"], stop.get("place_id") or "", b""
    coords = f_double(1, waypoint["latitude"]) + f_double(2, waypoint["longitude"])
    return f_len(1, name.encode()) + f_len(2, coords) + (f_len(3, place_id.encode()) if place_id else b"") + flags


def trip_message(plan, stops, user_id, target_soc):
    """The updated_trip message for one PlanTrip2 plan; `stops` are the requested stops in order."""
    meta = plan["planIdentifierMetadata"]
    planned = sum(not w.get("isSystemAdded") for w in plan["waypoints"][1:])
    if planned != len(stops):
        raise ValueError(f"plan has {planned} of your stops, expected {len(stops)}")
    user_stops = iter(stops)
    destinations = [_destination(w, None if w.get("isSystemAdded") else next(user_stops))
                    for w in plan["waypoints"][1:]]  # waypoints[0] is the start
    if len(destinations) != len(meta["legs"]):
        raise ValueError(f"plan has {len(meta['legs'])} legs but {len(destinations)} stops")
    route = f_len(1, meta["abrpRouteId"].encode()) + b"".join(
        f_len(2, f_len(1, leg["abrpLegId"].encode()) + f_len(2, leg["routeRequest"].encode()) + f_len(3, dest))
        for leg, dest in zip(meta["legs"], destinations))
    settings = (f_float(1, target_soc) + f_float(2, target_soc) +
                b"".join(f_len(3, s.encode()) for s in SWITCHES) + b"".join(f_len(4, s.encode()) for s in FILTERS))
    return f_len(1, route) + f_len(2, settings) + f_len(3, f_len(1, user_id.encode()))


def end_trip_message(user_id):
    return (f_len(1, f_len(1, f"end_trip_{int(time.time() * 1000)}".encode())) + f_len(2, b"") +
            f_len(3, f_len(1, user_id.encode())))


def payload(trip):
    """SendParallaxPayload body (base64): {10: {2: trip}, 12: timestamp, 16: request id}, unsigned."""
    now = time.time()
    stamp = f_var(1, int(now)) + f_var(2, int((now % 1) * 1e9))
    return base64.b64encode(f_len(10, f_len(2, trip)) + f_len(12, stamp) + f_len(16, uuid.uuid4().bytes)).decode()


async def gql(api, operation, query, variables):
    """Run one GraphQL operation via rivian-python-client's plumbing; returns its `data`."""
    from rivian.rivian import BASE_HEADERS, GRAPHQL_GATEWAY  # not exported; POC shortcut
    headers = BASE_HEADERS | {"Csrf-Token": api._csrf_token, "A-Sess": api._app_session_token,
                              "U-Sess": api._user_session_token}
    body = {"operationName": operation, "query": query, "variables": variables}
    response = await api._Rivian__graphql_query(headers, GRAPHQL_GATEWAY, body)
    return (await response.json()).get("data") or {}


async def vehicle_position(api, vehicle_id):
    """(latitude, longitude, battery percent) from the vehicle's last reported state."""
    response = await api.get_vehicle_state(vehicle_id, {"gnssLocation", "batteryLevel"})
    state = (await response.json())["data"]["vehicleState"]
    location = state.get("gnssLocation") or {}
    return location.get("latitude"), location.get("longitude"), (state.get("batteryLevel") or {}).get("value")


async def saved_locations(api, user_id, vehicle_id):
    data = await gql(api, "savedLocations",
                     "query savedLocations($vehicleId: String!, $userId: String!) { mapSearchSavedLocations("
                     "vehicleId: $vehicleId, userId: $userId) { name userGivenName locationType address coordinate "
                     "{ latitude longitude } id } }", {"userId": user_id, "vehicleId": vehicle_id})
    return data.get("mapSearchSavedLocations") or []


async def share_location(api, vehicle_id, stop):
    data = await gql(api, "ParseAndShareLocationToVehicle",
                     "mutation ParseAndShareLocationToVehicle($locationUrl: String!, $vehicleId: String!, "
                     "$requiresWakeup: Boolean) { parseAndShareLocationToVehicle(str: $locationUrl "
                     "vehicleId: $vehicleId requiresWakeup: $requiresWakeup) { publishResponse { result } } }",
                     {"locationUrl": share_url(stop), "vehicleId": vehicle_id, "requiresWakeup": True})
    return ((data.get("parseAndShareLocationToVehicle") or {}).get("publishResponse") or {}).get("result") == 0


async def plan(api, vehicle_id, origin, stops, soc, target_soc):
    data = await gql(api, "PlanTrip2", PLAN_QUERY, plan_variables(vehicle_id, origin, stops, soc, target_soc))
    result = data.get("planTrip2") or {}
    return result.get("status"), result.get("plans") or []


async def send_trip(api, vehicle_id, trip):
    data = await gql(api, "SendUpdatedTrip",
                     "mutation SendUpdatedTrip($vehicleId: String!, $payload: String!) { sendParallaxPayload("
                     f'payload: $payload meta: {{ vehicleId: $vehicleId model: "{TRIP_MODEL}" '
                     "isVehicleModelOp: false requiresWakeup: true }) { success } }",
                     {"vehicleId": vehicle_id, "payload": payload(trip)})
    return bool((data.get("sendParallaxPayload") or {}).get("success"))
