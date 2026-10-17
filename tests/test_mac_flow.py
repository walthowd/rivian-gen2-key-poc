"""Drive ble_mac against a simulated truck (fake bleak client, fake keys).

The fake truck verifies both auth MACs, replies on R, and answers the first T subscribe with
the CoreBluetooth "Authentication is insufficient" error, like an unpaired truck would.
"""
import argparse
import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    import ble_mac
    from bleak.exc import BleakError
except ImportError:  # bleak not installed
    ble_mac = None
import protocol  # noqa: E402

SECRET, PHONE, VEHICLE = os.urandom(32), os.urandom(16), os.urandom(16)
_real_sleep = asyncio.sleep
VAS = "00000000-1111-2222-3333-444444444444"


class Char:
    def __init__(self, uuid, handle):
        self.uuid = uuid
        self.obj = type("Obj", (), {"handle": lambda _self, h=handle: h})()


class Service:
    def __init__(self):
        self.chars = {u: Char(u, i) for i, u in enumerate((protocol.Q, protocol.R, protocol.T))}

    def get_characteristic(self, uuid):
        return self.chars.get(uuid)


class Truck:
    """Stands in for BleakClient."""
    instances = []

    def __init__(self, device, disconnected_callback=None, timeout=0, deny_t=1):
        self.services = type("S", (), {"get_service": lambda _s, u: Service() if u == protocol.PHONE_KEY_SERVICE else None,
                                       "__iter__": lambda _s: iter(())})()
        self.delegate = type("D", (), {"_characteristic_notify_callbacks": {},
                                       "_characteristic_notification_discriminators": {}})()
        self._backend = type("B", (), {"_delegate": self.delegate})()
        self.callbacks, self.t_attempts, self.deny_t = {}, 0, deny_t
        self.is_connected, self.mtu_size = True, 247
        self.auth2_ok = False
        Truck.instances.append(self)

    async def connect(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def start_notify(self, char, callback):
        registered = self.delegate._characteristic_notify_callbacks
        if char.obj.handle() in registered:
            raise ValueError("Characteristic notifications already started")
        registered[char.obj.handle()] = callback
        if char.uuid == protocol.T:
            self.t_attempts += 1
            if self.t_attempts <= self.deny_t:
                raise BleakError('Failed to update the notification status for characteristic 19: '
                                 'Error Domain=CBATTErrorDomain Code=5 "Authentication is insufficient."')
        self.callbacks[char.uuid] = callback

    async def read_gatt_char(self, char):
        return b""

    async def write_gatt_char(self, char, data, response):
        signed = protocol.parse_fields(protocol.parse_fields(bytes(data))[2][0])
        message_list, seq = signed[1][0], signed[2][0]
        mac = protocol.parse_fields(signed[5][0])[2][0]
        if seq == 1:
            message = protocol.parse_fields(protocol.parse_fields(message_list)[1][0])
            credentials = protocol.parse_fields(protocol.parse_fields(message[5][0])[1][0])
            assert credentials[1][0] == PHONE
            self.pnonce = credentials[2][0]
            assert mac == protocol._mac(SECRET, message_list, 1, PHONE, self.pnonce)
            self.vnonce = os.urandom(16)
            creds = protocol.f_len(1, VEHICLE) + protocol.f_len(2, self.vnonce)
            reply_list = protocol.f_len(1, protocol.f_var(1, 2) + protocol.f_len(5, protocol.f_len(1, creds)))
            reply_mac = protocol._mac(SECRET, reply_list, 1, VEHICLE, self.pnonce, self.vnonce)
            reply = protocol._signed(reply_list, 1, reply_mac)
            asyncio.get_running_loop().call_later(0.01, self.callbacks[protocol.R], None, bytearray(reply))
        else:
            assert mac == protocol._mac(SECRET, message_list, 2, PHONE, self.pnonce, self.vnonce)
            self.auth2_ok = True


def args(**overrides):
    values = dict(scan=1, pair_wait=5, hold=0, model=b"test-model")
    values.update(overrides)
    return argparse.Namespace(**values)


@unittest.skipIf(ble_mac is None, "bleak not installed")
class MacFlow(unittest.TestCase):
    def run_flow(self, truck_factory):
        async def find(*_a, **_k):
            return type("Device", (), {"address": "SIMULATED"})()
        Truck.instances.clear()
        with mock.patch.object(ble_mac, "BleakClient", truck_factory), \
                mock.patch.object(ble_mac.BleakScanner, "find_device_by_filter", find), \
                mock.patch.object(ble_mac.asyncio, "sleep", lambda _s: _real_sleep(0)), \
                mock.patch.object(ble_mac, "preflight", lambda: None):
            return ble_mac.pair(SECRET, PHONE, VEHICLE, VAS, args())

    def test_pairs_after_insufficient_authentication(self):
        self.assertTrue(self.run_flow(Truck))
        truck = Truck.instances[-1]
        self.assertTrue(truck.auth2_ok)
        self.assertEqual(truck.t_attempts, 2)

    def test_pairs_when_macos_retries_transparently(self):
        self.assertTrue(self.run_flow(lambda *a, **k: Truck(*a, deny_t=0, **k)))
        self.assertEqual(Truck.instances[-1].t_attempts, 1)

    def test_wrong_key_fails_verification(self):
        global SECRET
        real, SECRET = SECRET, os.urandom(32)
        try:
            with mock.patch.object(ble_mac.protocol, "verify_auth1_response",
                                   side_effect=ValueError("vehicle HMAC verification FAILED")):
                self.assertFalse(self.run_flow(Truck))
        finally:
            SECRET = real


if __name__ == "__main__":
    unittest.main()
