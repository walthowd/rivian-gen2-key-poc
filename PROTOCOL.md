# Gen 2 Rivian phone-key pairing over BLE

What a phone (or this POC) does to become a working phone key on a Gen 2 R1S/R1T.
Everything here was verified against one 2026 R1S. The message layouts were confirmed
byte-for-byte against an over-the-air capture of the official Android app pairing.

## Overview

```
 cloud                         phone / Mac                         truck (in Set Up)
   |  enrollPhone(publicKey)  ->   |                                     |
   |  <- vasPhoneId, identityId    |                                     |
   |                               |-- connect, subscribe R ----------->|
   |                               |-- auth#1 on Q (phone id + nonce) ->|
   |                               |<- reply on R (vehicle id + nonce) -|   both sides prove
   |                               |-- auth#2 on Q (client info) ------>|   the shared key
   |                               |-- subscribe T --------------------->|
   |                               |<- ATT error 0x05 (insufficient auth)|
   |                               |== SMP: LESC Just Works, IRK both ==|
   |                               |-- subscribe T (encrypted) -------->|  OK
   |  <- truck reports isPaired=true                                    |
```

There is **no** response to auth#2. After the 0x05 the phone pairs, and the truck reports
the key as paired to the cloud by itself. No extra cloud call is needed.

## Keys and identifiers

| Name | Source | Use |
|---|---|---|
| phone key pair | generated locally (P-256) | public key sent in `enrollPhone` |
| `vasPhoneId` | cloud, `enrolledPhones[].vas.vasPhoneId` (UUID) | phone ID in BLE messages; `vasPhoneId` in commands |
| `identityId` | cloud, `enrolledPhones[].enrolled[].identityId` | `deviceId` in commands |
| `vasVehicleId` | cloud, `vehicles[].vas.vasVehicleId` (UUID, 32 hex) | vehicle ID in BLE messages **and** the truck's advertised service UUID |
| `vehiclePublicKey` | cloud, `vehicles[].vas.vehiclePublicKey` (P-256, X9.62 hex) | ECDH peer |

**Shared secret** (same for BLE and cloud commands):

```
secret = HKDF-SHA256(ikm = ECDH(phone_private, vehicle_public), salt = none, info = "", length = 32)
```

Cloud command signature (legacy `sendVehicleCommand`): `HMAC-SHA256(secret, command || unix_timestamp)` as hex.

## Advertising

The truck advertises its `vasVehicleId` as a 128-bit service UUID ("incomplete list") with
no local name, in Set Up and also outside it. It uses resolvable private addresses that
change periodically and when Set Up opens or times out. Scan by UUID, never by address or name.

## GATT

Primary service `72cddca3-ab00-4e94-bae5-868f93f8c6c0` (only usable in Set Up or once bonded):

| Char | UUID | Props | Role |
|---|---|---|---|
| — | `1eb74dc8-3c1c-45ab-9254-9f41596cd4d6` | read, write | unknown, reads 16 × `00`; not used |
| **Q** | `0823da14-040b-4914-bf7c-450afa2850da` | write | phone → truck, no encryption needed |
| **R** | `29919a3c-a697-4a6f-bd3b-d14860cc9bce` | read, notify, indicate | truck → phone, no encryption needed |
| S | `9a69aeff-e3fe-4e79-bb7d-5ae12272fd14` | write | phone → truck, **encrypted link only** |
| **T** | `5eaa65c0-57ee-4cf4-a3d5-a4aae20cbb0b` | read, notify, indicate | truck → phone, **encrypted link only** |

On the test truck the handles were Q `0x000c`, R `0x000e` (CCCD `0x000f`), S `0x0011`,
T `0x0013` (CCCD `0x0014`). Discover by UUID rather than relying on handles.

A separate service `0xFFF5` (Car Connectivity Consortium Digital Key) and an L2CAP CoC on
PSM `0xCC` are also present. They're used by Apple/Google Wallet digital keys, not this path.

### Service Changed quirk (why BlueZ shows no services)

The vehicle answers any write to the Service Changed CCCD (handle `0x0007`) with ATT error
**0x03 Write Not Permitted**. iOS, macOS and Android ignore this. **BlueZ does not**: it
subscribes to Service Changed on every connection, and when that fails it abandons its GATT
client ("Failed to initialize gatt-client") while still reporting `ServicesResolved=true`, so
D-Bus clients such as bleak (and Home Assistant) see **no services at all**. Verified with
BlueZ 5.82. This is why the Linux path here uses a raw ATT socket instead of bleak.

## Messages

All messages are protobuf. Field numbers are all you need (names are descriptive, not official).

```
Envelope        { 2: Signed }
Signed          { 1: MessageList, 2: seq (uint32), 3: excludes_phone_nonce (bool),
                  4: excludes_vehicle_nonce (bool), 5: Signature }
Signature       { 1: algorithm (1 = HMAC-SHA256), 2: mac (32 bytes) }
MessageList     { 1: Message (repeated) }
Message         { 1: transaction_id, 5: Auth, 9: ClientInfo }        # 5 and 9 are a oneof
Auth            { 1: Credentials }
Credentials     { 1: id (16 bytes), 2: nonce (16 bytes) }
ClientInfo      { 1: Device }
Device          { 2: model (string) }
```

**MAC** over the serialized `MessageList` (fields 3/4 drop the phone/vehicle nonce term):

```
mac = HMAC-SHA256(secret, MessageList || seq (uint32 LE) || sender_id (16) || phone_nonce || vehicle_nonce)
```

| Step | Direction | Content | seq | Sender ID | Nonces in MAC |
|---|---|---|---|---|---|
| auth#1 | Q | Message{1: 1, 5: Auth{Credentials{phone_id, phone_nonce}}}; Signed.4 = 1 (no vehicle nonce yet) | 1 | phone_id | phone |
| reply | R | Message{5: Auth{Credentials{vasVehicleId, vehicle_nonce}}} | from truck | vasVehicleId | phone + vehicle |
| auth#2 | Q | Message{1: 3, 5: Auth{Credentials{}}} + Message{1: 5, 9: ClientInfo{Device{2: model}}} | 2 | phone_id | phone + vehicle |

- auth#1 is 90 bytes. auth#2 is 62 + len(model) bytes (the phone sent `"moto g play - 2024"` → 80 bytes).
- The phone must verify the reply's MAC before sending auth#2 (both nonces covered, so a replayed reply fails).
- Transaction IDs increment by 2 (1, 3, 5 …). seq increments by 1.
- An unsigned or wrongly signed auth#1 makes the truck disconnect immediately.

## Pairing (SMP) after auth#2

Subscribing to T (writing its CCCD) right after auth#2 fails with **ATT 0x05**. This is
expected; the official app gets it too. The central then starts SMP:

| | Phone request (captured) | Truck response |
|---|---|---|
| IO capability | KeyboardDisplay | NoInputNoOutput |
| AuthReq | Bonding, MITM, SC (`0x2d`) | Bonding, SC (`0x09`), **no MITM** |
| Max key size | 16 | 16 |
| Initiator keys | LTK IRK CSRK LinkKey | **IRK** |
| Responder keys | LTK IRK CSRK LinkKey | **IRK** |

The result is LE Secure Connections "Just Works", which takes a few seconds. The truck
distributes an IRK with identity address `00:00:00:00:00:00`. Two conditions are needed:

1. **The initiator must offer its IRK** (initiator key distribution includes IdKey). Without
   it the truck disconnects right after the pairing request.
2. **The initiator must accept Just Works**, i.e. not insist on MITM.

Once the link is encrypted, the T subscribe succeeds. The truck then marks the key as paired
and reports it to the cloud. No notifications arrive on T during pairing.

Phones and macOS meet both conditions by default. Linux (kernel 6.12 + BlueZ) by default does
neither: it only distributes an IRK when adapter privacy is enabled, and with any IO
capability other than NoInputNoOutput it adds MITM and then aborts Just Works. See [LINUX.md](LINUX.md).

## After pairing

- Cloud commands signed with the key are accepted (`sendVehicleCommand`, verified: open/close windows).
  Signature: hex `HMAC-SHA256(secret, command_name || unix_timestamp)`, as in rivian-python-client.
- Vehicle "model" operations (the Halloween costume, verified) use `SendParallaxPayload`, see below.

### Parallax operations (`SendParallaxPayload`)

```
command   { 1: operation name, 2: 3, 3: request id (16), 4: params (protobuf), 5: {1: sec, 2: nanos},
            7: vehicle id (string) }
payload   { 10: { 2: command }, 12: {1: sec, 2: nanos}, 16: request id,
            17: { 1: { 1: 1, 2: HMAC-SHA256(secret, command bytes) }, 2: identityId (string) } }
meta      { isVehicleModelOp: true, model: operation name, requiresWakeup: true, vehicleId }
```

The cloud answers `success: true` for unsigned or wrongly signed payloads too, but the vehicle
only acts on correctly signed ones. Results show up on the `parallaxMessages` subscription.

Security operations (no params), each confirmed by the vehicle publishing a state topic on
`parallaxMessages`:

| Operation | Effect | State topic |
|---|---|---|
| `security.video_monitoring.enable_video_monitoring` / `disable_video_monitoring` | Gear Guard motion cameras on / off | `security.video_monitoring.state`, field 1: 2 on, 1 off |
| `security.alarm.enable_panic` / `disable_panic` | car alarm (panic) on / off | `security.alarm.state` |

Gen 2 honks and flashes with the cloud commands `ACTIVATE_EXTERNAL_SOUND` and
`FLASH_EXTERNAL_LIGHTS` (signed like any `sendVehicleCommand`); the combined
`HONK_AND_FLASH_LIGHTS` is refused with `CONFLICT/VEHICLE_COMMAND_ERROR`.

### Legacy vs parallax routing (new R1s / R2s)

Older R1s accept legacy `sendVehicleCommand`. New R1s (2027+) and R2s accept only the signed
`SendParallaxPayload` above and refuse `sendVehicleCommand` (issues #4, #5). The Rivian app
decides **per command category** from the vehicle's `SupportedFeatures` (decompiled app,
`emm.e0`): for a command's category, if the matching `PVS_*_CMD` flag is `AVAILABLE` it sends
parallax, otherwise legacy. Model string / model year are **not** used to route.

```
query SupportedFeatures { currentUser { vehicles { id vehicle
  { vehicleState { supportedFeatures { name status } } } } } }
```

(`get_user_information` already returns this, so no extra query is needed.)

| Category | SupportedFeatures flag | Parallax operations |
|---|---|---|
| body | `PVS_BD_CMD` | `body.locks.lock` / `unlock`, `body.closures.open` / `close` |
| security | `PVS_SEC_CMD` | `security.alarm.enable_panic` / `disable_panic`, `security.video_monitoring.*` |
| comfort | `PVS_COMF_CMD` | `comfort.cabin.*` (preconditioning, temp, …) |
| energy | `PVS_ENRG_CMD` | `charging.energy.start_charging` / `stop_charging` / `set_charge_limit` |
| ota | `PVS_OTA_CMD` | `ota.install.install_now` |

Only `status == "AVAILABLE"` counts; `UPDATE_FIRMWARE` means not parallax-capable yet. (The app
additionally gates on a server-side rollout flag, `parallaxCommand`, that a client cannot read, so
auto-routing here means "the vehicle reports the category as AVAILABLE", which is the vehicle-side
half of the app's decision.)

Legacy command → parallax payload (field numbers from the app, confirmed against
rivian-python-client `body.proto`):

| Legacy command | Operation | `params` bytes |
|---|---|---|
| `LOCK_ALL_CLOSURES_FEEDBACK` | `body.locks.lock` | *(empty)* |
| `UNLOCK_ALL_CLOSURES` | `body.locks.unlock` | `08 01` (field 1 = all) |
| `OPEN_FRUNK` / `CLOSE_FRUNK` | `body.closures.open` / `close` | `0a 01 05` (ClosureId FRUNK=5) |
| `OPEN_LIFTGATE_UNLATCH_TAILGATE` | `body.closures.open` | `0a 01 07` (LIFTGATE; R1T uses `06` TAILGATE) |
| `OPEN_CHARGE_PORT_DOOR` / `CLOSE_…` | `body.closures.open` / `close` | `0a 01 0a` (CHARGE_PORT=10) |
| `OPEN_ALL_WINDOWS` / `CLOSE_ALL_WINDOWS` | `body.closures.open` / `close` | `0a 02 90 4e` (GROUP_WINDOWS=10000) |
| `PANIC_ON` / `PANIC_OFF` | `security.alarm.enable_panic` / `disable_panic` | *(empty)* |
| `VEHICLE_CABIN_PRECONDITION_ENABLE` / `DISABLE` | `comfort.cabin.enable_preconditioning` / `disable_` | *(empty)* |
| `CABIN_PRECONDITIONING_SET_TEMP` | `comfort.cabin.set_preconditioning_temperature` | `0d <float32 LE °C>` (21.0 = `0d 00 00 a8 41`) |
| `START_CHARGING` / `STOP_CHARGING` | `charging.energy.start_charging` / `stop_charging` | *(empty)* |
| `CHARGING_LIMITS` | `charging.energy.set_charge_limit` | `08 <percent>` (80 = `08 50`) |
| `CABIN_HVAC_*_SEAT_HEAT` / `_VENT` | `comfort.cabin.set_cabin_surface` | see below |
| `CABIN_HVAC_STEERING_HEAT` | `comfort.cabin.set_cabin_surface` | see below |
| `CABIN_HVAC_DEFROST_DEFOG` | `comfort.cabin.set_defrost_defog` | `08 04` off, `08 03` on (DEFOG_DEFROST) |

`set_cabin_surface` is `{1: instance, 2: level, 3: status, 4: device}`, all enums (proto3 omits a
field left at 0, so level 0 drops field 2). instance (CabinSurface): STEERING_WHEEL=1, ROW_1_LEFT=5,
ROW_1_RIGHT=7, ROW_2_LEFT=8, ROW_2_RIGHT=10, ROW_3_LEFT=11, ROW_3_RIGHT=13. device
(ConditioningType): HEAT=1, VENT=2. status: OFF=1, ON=2. level (a32): LEVEL1=1, LEVEL2=2, LEVEL3=3.
The app maps the legacy "level" int through `SurfaceHvacStatus`: **seats** take `0,2,3,4` (off, L1, L2,
L3) and the **steering wheel** takes `0,1,2,3`. Example left-seat heat low =
`08 05 10 01 18 02 20 01`; steering off = `08 01 18 01 20 01`.

`closure` is a packed repeated `ClosureId` at field 1, so a single closure is `0a 01 <id>` and all
windows `0a 02 90 4e`.

`HonkHorn`, `FlashLights` and `WakeVehicle` have **no** parallax operation: `wsg.b()` returns `""`
for them and `emm.e0` classifies them as category UNKNOWN, so the app always sends them as legacy
`sendVehicleCommand`. They work on older R1s; on a parallax-only vehicle that refuses legacy they
have no path. Wake *appears* to work on R2s only because every parallax send carries
`meta.requiresWakeup: true`, so the cloud wakes the vehicle to deliver any parallax command — that
is a side effect of other commands, not a standalone wake op.

In the POC: `command <name>` auto-routes from `SupportedFeatures`; `--parallax` / `--legacy` force a
path and `command --features` prints the per-command routing for a vehicle.

### Gear Guard live camera streaming (Kinesis WebRTC)

`security.video_monitoring.start_live_streaming` (signed, params field 4 = `{1: camera, 2: device
id}`) makes the vehicle a KVS WebRTC master for one camera; camera values (RivianMotionCamera): 1
front, 2 bed, 3 left, 4 right, 5 rear, 6 interior. The cloud returns the viewer config (presigned
signaling endpoint ~1h, channel ARN, ICE servers) on the GraphQL subscription
`GearGuardLiveConfigSubscription($vehicleId, $commandId){ gearGuardLiveConfig { endpoint channelArn
role iceServers { url username credential ttl } } }`.

- **Correlation:** `commandId` must equal the start op's parallax request id (fields 3 and 16),
  formatted as 32 lowercase hex chars (no dashes). This, not the device id, is what the cloud keys
  the config delivery on. Open the subscription, then send start with the same request id.
- **Device id** (field 4.2): just a label for the viewer device. Testing showed the vehicle accepts
  any non-empty string here (a random UUID, our vasPhoneId, even a plain word) once in-vehicle
  consent is granted; it does **not** have to be a registered digital key. The official app happens
  to send its CCC key's `identityId`, but the vehicle doesn't require it, so a plain phone key
  streams fine. (Earlier "only a cccKeyId works" results were an artifact of the one-session-at-a-
  time limit below, not the id value.)
- **Viewer signaling:** join the presigned endpoint as viewer; send `{senderClientId:
  "ConsumerViewer", action: "SDP_OFFER", recipientClientId: "", messagePayload: base64(offer)}`,
  and ICE as `{senderClientId: "ConsumerViewer", action: "ICE_CANDIDATE", messagePayload:
  base64(candidate)}`. The `senderClientId` is required or the master won't answer.
- **One session at a time:** the vehicle serves a single live session; a start is refused while a
  previous one (e.g. the app's live view) is still active or clearing. This is what made arbitrary
  device ids look like they "sometimes" worked.
- **Limits (vehicle-enforced, not in the app):** a per-session cap (teardown reason SESSION_LIMIT,
  ~3 min observed) and a daily cap of **1 hour/day** (DAILY_LIMIT; the
  `gearguard_streaming.privacy.*_daily_limit` topic reports HIT/NOT_HIT + a next-reset Unix-seconds
  timestamp). Other teardown reasons: not in Park, feature disabled, in service/transport, OTA in
  progress, consent not given. Account prerequisites: Connect+ subscription and precise location
  sharing opted in.

Halloween operations (prefix `holiday_celebration.car_costume.`), params as protobuf fields:

| Operation | Params | Effect |
|---|---|---|
| `set_holiday_celebration_enabled` | `1: 1` / empty | mode on / off |
| `set_car_costume` | `1: 3 (Ghostbusters), 2: {11: show, 12: trigger}` | show: 2 random, 3 Ecto-1, 4 Proton Pack, 5 Slimer, 6 Ghost Trap; trigger 1 manual, 2 motion |
| `play_car_costume_effect` | `1: 1..8` | one of the 8 sound effects |
| `update_car_costume_settings` | `1: volume`, `2: music on/off`, `3: track (1 Ghostbusters, 2 Wraith Hunt, 3 Spirits)`, `7: overhead lights` | settings |
- **Not covered:** the encrypted S/T channel for local (no-cloud) commands and passive entry.
  Their message formats are not documented here yet.

### Navigation (cloud only, no key)

Seen in the app's traffic and confirmed on a Gen 2 R1S; nothing is signed with the key.

- **The vehicle reports its route** on the `parallaxMessages` subscription, topic
  `navigation.navigation_service.trip_info` (protobuf; empty when not navigating, destination
  names and place ids appear as plain strings), plus `…trip_progress` every 5 s while
  navigating. The cloud answers success for anything, so this is the only real confirmation.
- **Send one place (starts navigating):** `ParseAndShareLocationToVehicle(str, vehicleId, requiresWakeup)` where `str`
  is a link like `https://telenav.id/entity?geo_coordinates=LAT,LNG&entity_id=<Google place
  id>&name=…&nav_coordinates=LAT,LNG&address=…&source_type=telenav`. Success is
  `publishResponse.result == 0`. Rivian returns INTERNAL_SERVER_ERROR for a telenav link without
  `entity_id`; Google Maps links and `geo:` URIs are accepted too. `requiresWakeup` wakes the
  vehicle; it shows the route ~30 s later. A share arriving while the vehicle goes to sleep is
  lost (no error), so wait for `trip_info` and re-send.
- **Send a trip (what `trip` uses):** `sendTripToVehicle(attrs: { vehicleId, requiresWakeup,
  routePreferences { avoidFerries, avoidHighways, avoidTolls }, preferences { avoidAdapterRequired,
  networks: [{ networkId }] }, waypoints: [{ address: { address, addressSourceId (Google place
  id), addressSourceType: "google", latitude, longitude, name }, minArrivalSoC (last stop) }] })`
  with the vehicle's location as the first waypoint (`name: "Vehicle location"`, empty ids).
  Returns `true`. The vehicle plans the route and charging stops itself and starts navigating;
  its `trip_info` then holds destinations at `3.3.1` and charging stops at `3.3.2 = { 1: charger
  id, 2: name, 3: { 1: lat, 2: lng }, 4: charge seconds, 6: arrival SoC, … }`, plus the starting
  SoC at top-level field 5. This is the app's trip planner "Go".
  **If a trip is already active, the vehicle merges:** the new stops go first and existing stops
  not in the new list are kept after them. To replace a trip, end it first (the app's planner
  starts from no active trip); to add a stop, this merge is all you need.
- **Replace the active route with a pre-planned one (older app path):** plan with `PlanTrip2` (waypoints: the vehicle's location first, then the stops;
  start SoC, arrival SoC, charging networks), then `SendUpdatedTrip`, a `sendParallaxPayload` with
  `meta { model: "c2v_navigation.trip_copilot.updated_trip", isVehicleModelOp: false,
  requiresWakeup: true }` and this unsigned payload:

```
payload   { 10: { 2: trip }, 12: {1: sec, 2: nanos}, 16: request id (16) }      (no field 17)
trip      { 1: route, 2: settings, 3: { 1: user id } }
route     { 1: plan.planIdentifierMetadata.abrpRouteId, 2: leg (repeated) }
leg       { 1: legs[i].abrpLegId, 2: legs[i].routeRequest ("v1:{…route_token…}"), 3: destination }
destination { 1: name, 2: { 1: lat (double), 2: lng (double) }, 3: place id or charger entityId,
              4: 1, 5: 1 (both only on charging stops the planner added) }
settings  { 1: arrival SoC (float), 2: arrival SoC (float), 3: "switchExcludeMotorway:false" …,
            4: "switchTeslaFilter:true" … (charging network filters) }
```

  Destination `i` is `plan.waypoints[i + 1]` (index 0 is the start). Rebuilding a captured
  trip from its `PlanTrip2` response this way matches the app's bytes exactly.
  **The vehicle ignores an updated trip when it isn't navigating**, so share the first stop
  first (as the app did), wait for `trip_info`, then send the trip. The vehicle then navigates
  the user's stops but drops the planned charging stops and has no charge estimates (the app
  shows arrival range "0% · --"); `sendTripToVehicle` doesn't have that problem.
- **Add a stop to the active route:** sending just the new stop via `sendTripToVehicle` puts it
  first (the merge above). `trip --add` instead reads the active destinations from `trip_info`
  (field 3, each `3.3.1 = { 1: { 1: lat, 2: lng } (doubles), 4: name, 5: place id }`), inserts the
  new stop where asked, ends the trip and sends the complete list, so the order is exactly ours.
- **End the trip:** the same message with `trip { 1: { 1: "end_trip_<unix ms>" }, 2: empty,
  3: { 1: user id } }`. Works whether the vehicle is awake or asleep; `trip_info` becomes empty.

## Things that are NOT needed

- No extra cloud call after the BLE handshake (`EnrollKeyFob` is the hardware-fob path, unrelated).
- No reads/writes of the `1eb74dc8` characteristic, no Service Changed subscription, no delays.
- No CCC / Digital Key operations.
