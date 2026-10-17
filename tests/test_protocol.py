"""Offline protocol tests: no Bluetooth, keys, cloud or truck. All values are fake."""
import hashlib
import hmac
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import protocol  # noqa: E402

SECRET = b"s" * 32
PHONE = b"p" * 16
VEHICLE = b"v" * 16
PNONCE = b"n" * 16
VNONCE = b"r" * 16


def vehicle_reply(vehicle=VEHICLE, secret=SECRET, flags=(0, 0), include_id=True, seq=1):
    """Independently spelled-out reply layout (fixed one-byte lengths), as observed on air."""
    credentials = (b"\x0a\x10" + vehicle if include_id else b"") + b"\x12\x10" + VNONCE
    auth = b"\x0a" + bytes([len(credentials)]) + credentials
    message = b"\x2a" + bytes([len(auth)]) + auth
    message_list = b"\x0a" + bytes([len(message)]) + message
    mac = hmac.new(secret, message_list + struct.pack("<I", seq) + vehicle
                   + (b"" if flags[0] else PNONCE) + (b"" if flags[1] else VNONCE), hashlib.sha256).digest()
    signed = b"\x0a" + bytes([len(message_list)]) + message_list + bytes([0x10, seq])
    signed += (b"\x18\x01" if flags[0] else b"") + (b"\x20\x01" if flags[1] else b"")
    signed += b"\x2a\x24\x08\x01\x12\x20" + mac
    return b"\x12" + bytes([len(signed)]) + signed


def signed_parts(message):
    envelope = protocol.parse_fields(message)
    assert set(envelope) == {2}, "messages to the truck carry only the signed block"
    signed = protocol.parse_fields(envelope[2][0])
    signature = protocol.parse_fields(signed[5][0])
    return signed[1][0], signed[2][0], signature[2][0], signed


class Auth1(unittest.TestCase):
    def test_size_matches_real_phone(self):
        self.assertEqual(len(protocol.build_auth1(SECRET, PHONE, PNONCE)), 90)

    def test_layout_and_mac(self):
        message_list, seq, mac, signed = signed_parts(protocol.build_auth1(SECRET, PHONE, PNONCE))
        self.assertEqual(seq, 1)
        self.assertEqual(signed[4], [1])
        message = protocol.parse_fields(protocol.parse_fields(message_list)[1][0])
        self.assertEqual(message[1], [1])  # transaction id
        credentials = protocol.parse_fields(protocol.parse_fields(message[5][0])[1][0])
        self.assertEqual((credentials[1][0], credentials[2][0]), (PHONE, PNONCE))
        expected = hmac.new(SECRET, message_list + struct.pack("<I", 1) + PHONE + PNONCE, hashlib.sha256).digest()
        self.assertEqual(mac, expected)


class Auth2(unittest.TestCase):
    def test_layout_and_mac(self):
        message = protocol.build_auth2(SECRET, PHONE, PNONCE, VNONCE, model=b"moto g play - 2024")
        self.assertEqual(len(message), 80)  # same size as the captured phone message with this model
        message_list, seq, mac, signed = signed_parts(message)
        self.assertEqual(seq, 2)
        self.assertNotIn(4, signed)
        first, second = protocol.parse_fields(message_list)[1]
        first, second = protocol.parse_fields(first), protocol.parse_fields(second)
        self.assertEqual((first[1], second[1]), ([3], [5]))
        self.assertEqual(protocol.parse_fields(first[5][0]), {1: [b""]})  # empty credentials
        info = protocol.parse_fields(protocol.parse_fields(second[9][0])[1][0])
        self.assertEqual(info[2], [b"moto g play - 2024"])
        expected = hmac.new(SECRET, message_list + struct.pack("<I", 2) + PHONE + PNONCE + VNONCE,
                            hashlib.sha256).digest()
        self.assertEqual(mac, expected)


class VehicleReply(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(protocol.verify_auth1_response(vehicle_reply(), SECRET, VEHICLE, PNONCE), (VNONCE, 1))

    def test_id_optional(self):
        self.assertEqual(protocol.verify_auth1_response(vehicle_reply(include_id=False), SECRET, VEHICLE, PNONCE),
                         (VNONCE, 1))

    def test_wrong_vehicle(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            protocol.verify_auth1_response(vehicle_reply(vehicle=b"x" * 16), SECRET, VEHICLE, PNONCE)

    def test_wrong_key(self):
        with self.assertRaisesRegex(ValueError, "HMAC"):
            protocol.verify_auth1_response(vehicle_reply(secret=b"k" * 32), SECRET, VEHICLE, PNONCE)

    def test_nonce_exclusion_refused(self):
        for flags in ((1, 0), (0, 1)):
            with self.assertRaisesRegex(ValueError, "omits"):
                protocol.verify_auth1_response(vehicle_reply(flags=flags), SECRET, VEHICLE, PNONCE)

    def test_truncated(self):
        with self.assertRaises(ValueError):
            protocol.verify_auth1_response(vehicle_reply()[:40], SECRET, VEHICLE, PNONCE)


if __name__ == "__main__":
    unittest.main()
