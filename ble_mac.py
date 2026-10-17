"""macOS transport: CoreBluetooth via bleak.

CoreBluetooth does the hard part for us. When the truck answers the T subscribe with ATT
error 0x05 (Insufficient Authentication), macOS runs LE Secure Connections "Just Works"
pairing on its own (always distributing its IRK, which the truck requires) and re-issues the
subscribe — exactly what a phone does. No adapter configuration is needed; macOS just shows a
"Connection Request from: Rivian Key …" dialog that the user confirms with Connect.
"""
import asyncio
import os
import time

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

import protocol
from common import log

# Log *why* the vehicle disconnected (bleak drops the CoreBluetooth error). The code tells
# apart e.g. a stale bond (CBError 14 "peer removed pairing information") from a timeout (6).
try:
    from bleak.backends.corebluetooth import CentralManagerDelegate as _cmd_module  # noqa: E402
    _original_did_disconnect = _cmd_module.CentralManagerDelegate.did_disconnect_peripheral
except (ImportError, AttributeError):  # bleak internals changed: lose this detail, keep working
    _cmd_module = None


def _did_disconnect_logged(self, central, peripheral, error):
    if error is not None:
        log.debug(f"disconnect reason: CBError domain={error.domain()} code={error.code()} "
                  f"{error.localizedDescription()}")
    else:
        log.debug("disconnect reason: none given (normal disconnect)")
    return _original_did_disconnect(self, central, peripheral, error)


if _cmd_module is not None:
    _cmd_module.CentralManagerDelegate.did_disconnect_peripheral = _did_disconnect_logged


STALE_BOND = 'Your Mac still remembers an old pairing with the vehicle. Open System Settings > Bluetooth, forget "Rivian Key …", then run pair.py again.'


def preflight():
    """Facts that explain most failures: Bluetooth permission, terminal app, existing bonds."""
    try:
        from CoreBluetooth import CBManager
        auth = {0: "not determined (macOS will ask)", 1: "restricted", 2: "DENIED", 3: "allowed"}
        log.debug(f"Bluetooth permission: {auth.get(CBManager.authorization(), CBManager.authorization())}"
                  f" (granted per app; terminal={os.environ.get('TERM_PROGRAM', '?')})")
    except Exception as error:  # noqa: BLE001
        log.debug(f"Bluetooth permission: unknown ({error})")
    try:
        import json
        import subprocess
        data = json.loads(subprocess.run(["system_profiler", "SPBluetoothDataType", "-json"],
                                         capture_output=True, text=True, timeout=10).stdout or "{}")
        bonded = "Rivian Key" in json.dumps(data)
        log.debug(f"macOS Bluetooth list already has a 'Rivian Key' device: {'yes' if bonded else 'no'}")
        if bonded:
            log("warning: " + STALE_BOND + " (fine to ignore if this key is already paired)")
    except Exception as error:  # noqa: BLE001
        log.debug(f"Bluetooth device list: unavailable ({error})")


async def find_truck(vas_vehicle_id, timeout):
    """macOS hides MAC addresses; match the truck by its advertised service UUID."""
    log(f"scanning up to {timeout:.0f}s for the truck (service <vas_vehicle_id>)")

    seen, rivian_named = set(), set()

    def match(device, adv):
        seen.add(device.address)
        if (device.name or adv.local_name or "").startswith("Rivian"):
            rivian_named.add(device.address)
        if vas_vehicle_id in (adv.service_uuids or []):
            log.secret(device.name, "ble-name", whole_word=True)
            log(f"found the vehicle (signal {adv.rssi} dBm)")
            log.debug(f"advertisement: name={adv.local_name!r} uuids={adv.service_uuids} "
                      f"manufacturer_ids={list(adv.manufacturer_data)} tx_power={adv.tx_power}")
            return True
        return False

    device = await BleakScanner.find_device_by_filter(match, timeout=timeout)
    log.debug(f"scan: {len(seen)} devices seen, {len(rivian_named)} named 'Rivian…', "
              f"vehicle {'found' if device else 'NOT found'}")
    return device


def dump_gatt(client):
    for service in client.services:
        log.debug(f"service {service.uuid}")
        for char in service.characteristics:
            log.debug(f"  char {char.uuid} [{','.join(char.properties)}]")


def _clear_failed_notify(client, char):
    """bleak leaves the callback registered when start_notify fails, so a retry would raise
    'already started'. Drop that stale entry (private bleak state, CoreBluetooth backend)."""
    delegate = getattr(getattr(client, "_backend", None), "_delegate", None)
    if delegate is None:
        return
    try:
        handle = char.obj.handle()
        delegate._characteristic_notify_callbacks.pop(handle, None)
        delegate._characteristic_notification_discriminators.pop(handle, None)
    except AttributeError:
        log.debug("could not reset bleak notify state (bleak internals changed?)")


async def subscribe_t(client, t_char, on_t, pair_wait):
    """The first T subscribe is expected to hit ATT 0x05; macOS then pairs. In our test macOS
    paired and retried transparently (no error surfaced). If an error does surface, retry
    until the bond is up or pair_wait expires (the user may need to accept a dialog)."""
    deadline = time.monotonic() + pair_wait
    started = time.monotonic()
    attempt = 0
    kicked = False
    while True:
        attempt += 1
        try:
            task = asyncio.ensure_future(client.start_notify(t_char, on_t))
            while not task.done():
                await asyncio.wait({task}, timeout=10)
                if not task.done():
                    waited = time.monotonic() - started
                    if time.monotonic() > deadline:
                        task.cancel()
                        log(f"gave up after {waited:.0f}s — macOS never finished pairing "
                            "(was the Connect dialog clicked?)")
                        return False
                    log(f"still waiting for macOS to pair ({waited:.0f}s) — click Connect if a dialog is showing")
            task.result()
            log(f"T subscribe (attempt {attempt}) acknowledged after {time.monotonic() - started:.1f}s")
            return True
        except BleakError as error:
            _clear_failed_notify(client, t_char)
            text = str(error)
            insufficient = "insufficient" in text.lower() or "Code=5" in text or "Code=15" in text
            log(f"T subscribe (attempt {attempt}) failed after {time.monotonic() - started:.1f}s: {text}")
            if not client.is_connected:
                log("link dropped — the truck rejected pairing, or Set Up timed out")
                return False
            if not insufficient and attempt > 1:
                return False
            if time.monotonic() > deadline:
                log(f"gave up after {pair_wait:.0f}s waiting for macOS to pair")
                return False
            if attempt == 1:
                log("expected ATT 0x05 — macOS should now pair (click Connect if asked)")
            elif not kicked:
                kicked = True  # a read of T is also encryption-gated and also triggers pairing
                try:
                    await client.read_gatt_char(t_char)
                except BleakError as read_error:
                    log(f"T read (pairing kick): {read_error}")
            await asyncio.sleep(2)


async def _pair(secret, phone_id, vehicle_id, vas_vehicle_id, args):
    preflight()
    device = await find_truck(vas_vehicle_id, args.scan)
    if device is None:
        log("truck not found — is it in Set Up for this key, and is Bluetooth allowed for this terminal?")
        return False

    disconnected = asyncio.Event()
    r_queue = asyncio.Queue()

    def on_disconnect(_client):
        log("disconnected")
        disconnected.set()

    def on_r(_char, data):
        log.debug(f"R notify {len(data)}B {bytes(data).hex()}")
        r_queue.put_nowait(bytes(data))

    def on_t(_char, data):
        # Shape only: T content after pairing is undocumented and could carry identifiers.
        try:
            shape = {f: [len(v) if isinstance(v, bytes) else "int" for v in vals]
                     for f, vals in protocol.parse_fields(bytes(data)).items()}
        except ValueError:
            shape = "not protobuf"
        log.debug(f"T notify {len(data)}B fields={shape}")

    log("connecting")
    client = BleakClient(device, disconnected_callback=on_disconnect, timeout=20)
    try:
        await client.connect()
    except asyncio.TimeoutError:
        log("connect timed out after 20s (vehicle changed its Bluetooth address? Set up timed out?)")
        return False
    async with client:
        log(f"connected (mtu {client.mtu_size})")
        dump_gatt(client)
        service = client.services.get_service(protocol.PHONE_KEY_SERVICE)
        chars = service and {n: service.get_characteristic(u)
                             for n, u in (("Q", protocol.Q), ("R", protocol.R), ("T", protocol.T))}
        if not chars or not all(chars.values()):
            log("phone-key service/characteristics missing — the truck only exposes them in Set Up")
            return False

        await client.start_notify(chars["R"], on_r)
        log("R subscribed")

        phone_nonce = os.urandom(16)
        message = protocol.build_auth1(secret, phone_id, phone_nonce)
        log.debug(f"auth#1 {len(message)}B {message.hex()}")
        await client.write_gatt_char(chars["Q"], message, response=True)
        log(f"auth#1 written ({len(message)}B)")

        try:
            response = await asyncio.wait_for(r_queue.get(), 8)
        except asyncio.TimeoutError:
            log("no reply to auth#1 within 8s (key not known to the truck yet? wrong driver's Set Up?)")
            return False
        vehicle_nonce, seq = protocol.verify_auth1_response(response, secret, vehicle_id, phone_nonce)
        log(f"auth#1 reply {len(response)}B — vehicle signature VERIFIED (seq {seq})")

        message = protocol.build_auth2(secret, phone_id, phone_nonce, vehicle_nonce, model=args.model)
        log.debug(f"auth#2 {len(message)}B {message.hex()}")
        await client.write_gatt_char(chars["Q"], message, response=True)
        log(f"auth#2 written ({len(message)}B)")

        log('pairing — macOS will show "Connection Request from: Rivian Key …": click Connect')
        started = time.monotonic()
        if not await subscribe_t(client, chars["T"], on_t, args.pair_wait):
            return False
        log.debug(f"T subscribe completed after {time.monotonic() - started:.1f}s")
        log("*** PAIRED — T subscribe succeeded on the encrypted link ***")
        if args.hold:
            try:
                await asyncio.wait_for(disconnected.wait(), args.hold)
            except asyncio.TimeoutError:
                pass
        return True


def pair(secret, phone_id, vehicle_id, vas_vehicle_id, args):
    """True = paired, False = failed (worth a retry), None = failed, retrying won't help."""
    try:
        return asyncio.run(_pair(secret, phone_id, vehicle_id, vas_vehicle_id, args))
    except (BleakError, ValueError, OSError, asyncio.TimeoutError) as error:
        log.exception(f"FAILED: {type(error).__name__}: {error}")
        if "Code=14" in str(error) or "Peer removed pairing information" in str(error):
            log(STALE_BOND)
            return None
        return False
