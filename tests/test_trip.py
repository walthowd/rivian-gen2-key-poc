"""Offline tests of the navigation messages; no account or vehicle access."""
import base64
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rivian_key
import trip
from protocol import parse_fields

USER = "02-00000000-0000-0000-0000-000000000000-00000000"
STOPS = [{"name": "Golf", "place_id": "ChIJgolf", "latitude": 40.5, "longitude": -91.5},
         {"name": "Stadium", "latitude": 39.0, "longitude": -94.5}]
PLAN = {
    "planIdentifierMetadata": {"abrpRouteId": "route-1", "legs": [
        {"abrpLegId": "leg:0:", "routeRequest": "v1:{a}"},
        {"abrpLegId": "leg:1:", "routeRequest": "v1:{b}"},
        {"abrpLegId": "leg:2:", "routeRequest": "v1:{c}"}]},
    "summary": {"totalDriveDistanceMeters": 300000, "totalTripDurationSeconds": 14400,
                "totalChargeDurationSeconds": 1800, "arrivalSOCPercent": 25, "destinationReachable": True},
    "waypoints": [
        {"latitude": 40.0, "longitude": -92.0, "isSystemAdded": False, "arrivalSOCPercent": 90},
        {"latitude": 40.5, "longitude": -91.5, "isSystemAdded": False, "arrivalSOCPercent": 70},
        {"latitude": 40.9, "longitude": -91.9, "isSystemAdded": True, "arrivalSOCPercent": 20,
         "charger": {"name": "Charger", "entityId": "charger-1", "chargeDurationSeconds": 1800}},
        {"latitude": 39.0, "longitude": -94.5, "isSystemAdded": False, "arrivalSOCPercent": 25}],
}


class TripMessages(unittest.TestCase):
    def test_trip_message_layout(self):
        fields = parse_fields(trip.trip_message(PLAN, STOPS, USER, 20))
        route = parse_fields(fields[1][0])
        self.assertEqual(route[1], [b"route-1"])
        legs = [parse_fields(leg) for leg in route[2]]
        self.assertEqual([leg[2][0] for leg in legs], [b"v1:{a}", b"v1:{b}", b"v1:{c}"])
        golf, charger, stadium = (parse_fields(leg[3][0]) for leg in legs)
        self.assertEqual((golf[1], golf[3], golf.get(4)), ([b"Golf"], [b"ChIJgolf"], None))
        self.assertEqual((charger[1], charger[3], charger[4], charger[5]), ([b"Charger"], [b"charger-1"], [1], [1]))
        self.assertEqual((stadium[1], stadium.get(3)), ([b"Stadium"], None))
        self.assertEqual(parse_fields(fields[3][0])[1], [USER.encode()])

    def test_coordinates_are_doubles(self):
        message = trip._destination(PLAN["waypoints"][1], STOPS[0])
        self.assertIn(trip.f_double(1, 40.5) + trip.f_double(2, -91.5), message)

    def test_stop_count_mismatch_is_refused(self):
        with self.assertRaises(ValueError):
            trip.trip_message(PLAN, STOPS + [STOPS[0]], USER, 20)

    def test_end_trip_and_unsigned_envelope(self):
        end = parse_fields(trip.end_trip_message(USER))
        self.assertTrue(parse_fields(end[1][0])[1][0].startswith(b"end_trip_"))
        self.assertEqual(end[2], [b""])
        outer = parse_fields(base64.b64decode(trip.payload(b"x")))
        self.assertEqual(parse_fields(outer[10][0])[2], [b"x"])
        self.assertEqual(len(outer[16][0]), 16)
        self.assertNotIn(17, outer)  # no signature: trips aren't signed with the key

    def test_share_url(self):
        query = parse_qs(urlparse(trip.share_url(STOPS[0])).query)
        self.assertEqual(query["geo_coordinates"], ["40.5,-91.5"])
        self.assertEqual((query["name"], query["entity_id"], query["source_type"]), (["Golf"], ["ChIJgolf"], ["telenav"]))
        self.assertEqual(trip.share_url(STOPS[1]),  # no place id: Rivian refuses telenav links without one
                         "https://www.google.com/maps/search/?api=1&query=39.0%2C-94.5")
        self.assertEqual(trip.share_url({"url": "geo:1,2"}), "geo:1,2")


class Places(unittest.TestCase):
    SAVED = [{"name": "123 Main St", "userGivenName": "Home", "address": "123 Main St",
              "coordinate": {"latitude": 1.5, "longitude": 2.5}}]

    def test_home_by_location_type(self):
        saved = [{"name": "9 Elm St", "userGivenName": None, "locationType": "RECENT",
                  "coordinate": {"latitude": 3.0, "longitude": 4.0}},
                 {"name": "1 Oak St", "userGivenName": None, "locationType": "FAVORITE_HOME",
                  "coordinate": {"latitude": 1.0, "longitude": 2.0}}]
        place = rivian_key.resolve_place("Home", saved)
        self.assertEqual((place["name"], place["latitude"]), ("Home", 1.0))
        self.assertIsNone(place["place_id"])
        self.assertEqual(rivian_key.resolve_place("9 elm st", saved)["name"], "9 Elm St")

    def test_coordinates_with_and_without_name(self):
        self.assertEqual(rivian_key.resolve_place("40.5, -91.5=Golf course", []),
                         {"name": "Golf course", "latitude": 40.5, "longitude": -91.5})
        self.assertEqual(rivian_key.resolve_place("40,-91", [])["name"], "40,-91")

    def test_saved_location_by_name(self):
        place = rivian_key.resolve_place("home", self.SAVED)
        self.assertEqual((place["name"], place["latitude"]), ("Home", 1.5))

    def test_unknown_place_lists_saved_names(self):
        with patch.object(rivian_key, "die", side_effect=SystemExit) as die, self.assertRaises(SystemExit):
            rivian_key.resolve_place("Work", self.SAVED)
        self.assertIn("'Home'", die.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
