"""Offline tests for key handling, HA import parsing and log redaction. All values are fake."""
import sys
import unittest
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import common  # noqa: E402
from rivian.utils import generate_key_pair, get_secret_key  # noqa: E402

import rivian_key  # noqa: E402


class Secret(unittest.TestCase):
    def test_matches_rivian_python_client(self):
        _, private_key = generate_key_pair()
        vehicle_public, _ = generate_key_pair()
        self.assertEqual(common.derive_secret(private_key, vehicle_public),
                         get_secret_key(private_key, vehicle_public))


class Redaction(unittest.TestCase):
    def test_uuid_forms_redacted(self):
        log = common.Log()
        phone = uuid4()
        log.secret(str(phone), "phone_id")
        text = f"id={phone} hex={phone.hex} HEX={phone.hex.upper()}"
        self.assertEqual(log.redact(text), "id=<phone_id> hex=<phone_id> HEX=<phone_id>")

    def test_patterns_redacted_without_registration(self):
        log = common.Log()
        text = log.redact("mail someone@example.com addr AA:BB:CC:DD:EE:01 zero 00:00:00:00:00:00 "
                          "vin 1ABCD23EFGH456789 hdr {'U-Sess': 'abc123', \"csrf-token\": \"xyz\"}")
        for leaked in ("someone@example.com", "AA:BB:CC:DD:EE:01", "1ABCD23EFGH456789", "abc123", "xyz"):
            self.assertNotIn(leaked, text)
        self.assertIn("00:00:00:00:00:00", text)

    def test_bleak_debug_lines(self):
        log = common.Log()
        line = ("Discovered device 9C473C0F-0162-A539-BBF6-E2A0D62E44E9: Rivian Key 12345 "
                "Write Characteristic 0823da14-040b-4914-bf7c-450afa2850da : b'\\x12X\\n,W\\x01G'")
        self.assertEqual(log.redact(line), "Discovered device <uuid#1>: Rivian Key <vin-suffix> "
                         "Write Characteristic 0823da14-040b-4914-bf7c-450afa2850da : <bytes>")

    def test_nearby_device_names(self):
        line = "Discovered device 1A2B3C4D-0000-1111-2222-333344445555: Someone's AirPods Pro @ RSSI: -60 (kCBAdvData"
        self.assertEqual(common.Log().redact(line), "Discovered device <uuid#1>: <device-name#1> @ RSSI: -60 (kCBAdvData")

    def test_pseudonyms_stable_within_run(self):
        log = common.Log()
        a, b = "1A2B3C4D-0000-1111-2222-333344445555", "9F8E7D6C-0000-1111-2222-333344445555"
        self.assertEqual(log.redact(f"{a} {b} {a.lower()}"), "<uuid#1> <uuid#2> <uuid#1>")

    def test_bluez_object_paths(self):
        self.assertEqual(common.Log().redact("/org/bluez/hci0/dev_AA_BB_CC_DD_EE_01"), "/org/bluez/hci0/dev_<bt-address>")

    def test_home_directory(self):
        self.assertNotIn(common.HOME, common.Log().redact(f"File {common.HOME}/x/pair.py"))

    def test_rivian_api_error_dump(self):
        # Shape of a RivianApiException / partial-data warning carrying a DriversAndKeys response.
        dump = ("(200, 'BAD_REQUEST'): {'data': {'getVehicle': {'invitedUsers': [{'firstName': 'Jane', "
                "'lastName': 'Doe', 'email': 'jane@example.com', 'devices': [{'deviceName': \"Jane's iPhone 15\", "
                "'hrid': 'K-9F3A', 'id': '11111111-2222-4333-8444-555555555555'}]}], "
                "'vas': {'vasVehicleId': 'aabbccddeeff00112233445566778899', "
                "'vehiclePublicKey': '04" + "ab" * 64 + "'}, 'name': \"Jane's R1S\"}}}")
        text = common.Log().redact(dump)
        for leaked in ("Jane", "Doe", "jane@", "iPhone", "K-9F3A", "0dbbbc43", "aabbccdd", "abababab", "R1S"):
            self.assertNotIn(leaked, text)

    def test_vehicle_named_like_ble_name(self):
        log = common.Log()
        log.secret("Rivian", "vehicle_name", whole_word=True)
        self.assertNotIn("12345", log.redact("name of peripheral changed to Rivian Key 12345"))

    def test_key_name_redacted(self):
        log = common.Log()
        log.secret("Jane's MacBook!", "key_name", whole_word=True)
        self.assertEqual(log.redact("pairing Jane's MacBook! now"), "pairing <key_name> now")

    def test_short_names_ignored(self):
        log = common.Log()
        log.secret("mac", "hostname", whole_word=True)  # too short to redact safely
        self.assertEqual(log.redact("MAC address"), "MAC address")

    def test_names_visible_on_screen_only(self):
        log = common.Log()
        log.secret("POC Mac", "key_name", whole_word=True)
        log.secret("11111111-2222-4333-8444-555555555555", "phone_id")
        line = "POC Mac phone 11111111-2222-4333-8444-555555555555"
        self.assertEqual(log.redact(line, screen=True), "POC Mac phone <phone_id>")
        self.assertEqual(log.redact(line), "<key_name> phone <phone_id>")

    def test_names_whole_word_only(self):
        log = common.Log()
        log.secret("Truck", "vehicle_name", whole_word=True)
        self.assertEqual(log.redact("Truck found the truckstop"), "<vehicle_name> found the truckstop")


class HomeAssistantImport(unittest.TestCase):
    entry = {"domain": "rivian", "data": {"user_session_token": "fake"}, "options": {}}

    def test_full_file(self):
        data = {"version": 1, "data": {"entries": [{"domain": "hue"}, self.entry]}}
        self.assertEqual(rivian_key.ha_rivian_entries(data), [self.entry])

    def test_single_entry_and_list(self):
        self.assertEqual(rivian_key.ha_rivian_entries(self.entry), [self.entry])
        self.assertEqual(rivian_key.ha_rivian_entries([self.entry, {"domain": "x"}]), [self.entry])


class FindPhone(unittest.TestCase):
    def test_matches_public_key_and_vehicle(self):
        user = {"enrolledPhones": [
            {"vas": {"vasPhoneId": "other", "publicKey": "04aa"}, "enrolled": [{"vehicleId": "V"}]},
            {"vas": {"vasPhoneId": "mine", "publicKey": "04BB"},
             "enrolled": [{"vehicleId": "W", "identityId": "x"}, {"vehicleId": "V", "identityId": "y"}]},
        ]}
        phone_id, enrolled = rivian_key.find_phone(user, "04bb", "V")
        self.assertEqual((phone_id, enrolled["identityId"]), ("mine", "y"))
        self.assertEqual(rivian_key.find_phone(user, "04cc", "V"), (None, None))


if __name__ == "__main__":
    unittest.main()
