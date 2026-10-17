"""Halloween operations: params match the Rivian app's captured requests; signature layout."""
import base64
import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import halloween  # noqa: E402
from protocol import parse_fields  # noqa: E402

P = halloween.PREFIX


class Operations(unittest.TestCase):
    def test_matches_app_requests(self):
        # (action, value, motion) -> (operation, params hex) as sent by the Rivian app
        cases = {
            ("on", None, False): ("set_holiday_celebration_enabled", "0801"),
            ("off", None, False): ("set_holiday_celebration_enabled", ""),
            ("show", "ecto1", True): ("set_car_costume", "080312045803" "6002"),
            ("show", "slimer", False): ("set_car_costume", "080312045805" "6001"),
            ("sound", "8", False): ("play_car_costume_effect", "0808"),
            ("music", "ghostbusters", False): ("update_car_costume_settings", "10011801"),
            ("music", "wraith", False): ("update_car_costume_settings", "10011802"),
            ("music", "off", False): ("update_car_costume_settings", "1000"),
            ("volume", "19", False): ("update_car_costume_settings", "0813"),
            ("lights", "off", False): ("update_car_costume_settings", "3800"),
        }
        for (action, value, motion), (op, params) in cases.items():
            self.assertEqual(halloween.operation(action, value, motion), (P + op, bytes.fromhex(params)))

    def test_rejects_bad_values(self):
        for action, value in (("show", "nope"), ("sound", "9"), ("sound", None), ("music", "jazz"),
                              ("volume", "99"), ("lights", "dim"), ("dance", None)):
            with self.assertRaises(ValueError):
                halloween.operation(action, value)


class Payload(unittest.TestCase):
    def test_layout_and_signature(self):
        secret = b"k" * 32
        op, params = halloween.operation("sound", "1")
        body = parse_fields(base64.b64decode(halloween.payload(op, params, "01-123", "17-abc", secret)))
        self.assertEqual(sorted(body), [10, 12, 16, 17])
        command = parse_fields(body[10][0])[2][0]
        fields = parse_fields(command)
        self.assertEqual((fields[1][0], fields[2][0], fields[4][0], fields[7][0]),
                         (op.encode(), 3, params, b"01-123"))
        self.assertEqual(fields[3][0], body[16][0])  # same request id
        signature = parse_fields(body[17][0])
        mac = parse_fields(signature[1][0])
        self.assertEqual(mac[1][0], 1)
        self.assertEqual(mac[2][0], hmac.new(secret, command, hashlib.sha256).digest())
        self.assertEqual(signature[2][0], b"17-abc")


if __name__ == "__main__":
    unittest.main()
