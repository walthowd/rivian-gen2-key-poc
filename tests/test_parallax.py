"""Offline tests for parallax command payloads and routing; no account access."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parallax


def user_with(flags, model="R2", vid="V"):
    feats = [{"name": k, "status": v} for k, v in flags.items()]
    return {"vehicles": [{"id": vid, "vehicle": {
        "model": model, "vehicleState": {"supportedFeatures": feats}}}]}


class Payloads(unittest.TestCase):
    """Byte-for-byte against the app (wsg.java/emm.java) and rivian body.proto."""

    def check(self, command, value, model, op, payload_hex):
        got_op, got = parallax.build(command, value, model)
        self.assertEqual(got_op, op)
        self.assertEqual(got.hex(), payload_hex)

    def test_locks(self):
        self.check("LOCK_ALL_CLOSURES_FEEDBACK", None, "R2", "body.locks.lock", "")
        self.check("UNLOCK_ALL_CLOSURES", None, "R2", "body.locks.unlock", "0801")

    def test_closures(self):
        self.check("OPEN_FRUNK", None, "R2", "body.closures.open", "0a0105")
        self.check("CLOSE_FRUNK", None, "R2", "body.closures.close", "0a0105")
        self.check("OPEN_ALL_WINDOWS", None, "R2", "body.closures.open", "0a02904e")
        self.check("OPEN_CHARGE_PORT_DOOR", None, "R2", "body.closures.open", "0a010a")

    def test_liftgate_depends_on_model(self):
        # R1T unlatches the tailgate (6); everything else opens the liftgate (7).
        self.check("OPEN_LIFTGATE_UNLATCH_TAILGATE", None, "R1T", "body.closures.open", "0a0106")
        self.check("OPEN_LIFTGATE_UNLATCH_TAILGATE", None, "R2", "body.closures.open", "0a0107")
        self.check("OPEN_LIFTGATE_UNLATCH_TAILGATE", None, "R1S", "body.closures.open", "0a0107")

    def test_value_commands(self):
        self.check("CABIN_PRECONDITIONING_SET_TEMP", "21", "R2",
                   "comfort.cabin.set_preconditioning_temperature", "0d0000a841")
        self.check("CHARGING_LIMITS", "80", "R2", "charging.energy.set_charge_limit", "0850")
        self.check("CHARGING_LIMITS", "100", "R2", "charging.energy.set_charge_limit", "0864")

    def test_security_and_energy_empty(self):
        self.check("PANIC_ON", None, "R2", "security.alarm.enable_panic", "")
        self.check("START_CHARGING", None, "R2", "charging.energy.start_charging", "")

    def test_cabin_surface_seat_heat(self):
        # set_cabin_surface z22: 1=instance 2=level 3=status 4=device; level 0 omits field 2.
        self.check("CABIN_HVAC_LEFT_SEAT_HEAT", "2", "R2",
                   "comfort.cabin.set_cabin_surface", "0805100118022001")
        self.check("CABIN_HVAC_LEFT_SEAT_HEAT", "0", "R2",
                   "comfort.cabin.set_cabin_surface", "080518012001")
        self.check("CABIN_HVAC_RIGHT_SEAT_HEAT", "4", "R2",
                   "comfort.cabin.set_cabin_surface", "0807100318022001")
        self.check("CABIN_HVAC_LEFT_SEAT_VENT", "4", "R2",
                   "comfort.cabin.set_cabin_surface", "0805100318022002")

    def test_cabin_surface_steering_uses_wheel_scale(self):
        self.check("CABIN_HVAC_STEERING_HEAT", "1", "R2",
                   "comfort.cabin.set_cabin_surface", "0801100118022001")
        self.check("CABIN_HVAC_STEERING_HEAT", "0", "R2",
                   "comfort.cabin.set_cabin_surface", "080118012001")

    def test_defrost(self):
        self.check("CABIN_HVAC_DEFROST_DEFOG", "1", "R2", "comfort.cabin.set_defrost_defog", "0803")
        self.check("CABIN_HVAC_DEFROST_DEFOG", "0", "R2", "comfort.cabin.set_defrost_defog", "0804")

    def test_invalid_levels_raise(self):
        # seats accept 0/2/3/4, steering 0/1/2/3
        self.assertRaises(ValueError, parallax.build, "CABIN_HVAC_LEFT_SEAT_HEAT", "1", "R2")
        self.assertRaises(ValueError, parallax.build, "CABIN_HVAC_STEERING_HEAT", "4", "R2")

    def test_temp_bounds(self):
        self.check("CABIN_PRECONDITIONING_SET_TEMP", "16", "R2",
                   "comfort.cabin.set_preconditioning_temperature", "0d00008041")
        for ok in ("0", "63.5"):  # LO / HI sentinels accepted
            parallax.build("CABIN_PRECONDITIONING_SET_TEMP", ok, "R2")
        for bad in ("-40", "15", "30", "100"):
            self.assertRaises(ValueError, parallax.build, "CABIN_PRECONDITIONING_SET_TEMP", bad, "R2")

    def test_charge_limit_bounds(self):
        # out-of-range (incl. negative, which used to hang the varint encoder) must raise, not spin
        for bad in ("-5", "0", "49", "101"):
            self.assertRaises(ValueError, parallax.build, "CHARGING_LIMITS", bad, "R2")
        self.assertEqual(parallax.build("CHARGING_LIMITS", "50", "R2")[1].hex(), "0832")


class Routing(unittest.TestCase):
    def test_available_flag_selects_parallax(self):
        feats = parallax.supported_features(user_with({"PVS_BD_CMD": "AVAILABLE"}), "V")
        self.assertTrue(parallax.category_available("LOCK_ALL_CLOSURES_FEEDBACK", feats))
        self.assertFalse(parallax.category_available("CHARGING_LIMITS", feats))  # PVS_ENRG_CMD absent

    def test_update_firmware_is_not_available(self):
        feats = parallax.supported_features(user_with({"PVS_BD_CMD": "UPDATE_FIRMWARE"}), "V")
        self.assertFalse(parallax.category_available("LOCK_ALL_CLOSURES_FEEDBACK", feats))

    def test_no_features_means_legacy(self):
        feats = parallax.supported_features(user_with({}), "V")
        self.assertFalse(parallax.category_available("LOCK_ALL_CLOSURES_FEEDBACK", feats))

    def test_honk_flash_have_no_parallax_equivalent(self):
        self.assertNotIn("ACTIVATE_EXTERNAL_SOUND", parallax.COMMANDS)
        self.assertNotIn("FLASH_EXTERNAL_LIGHTS", parallax.COMMANDS)
        self.assertNotIn("WAKE_VEHICLE", parallax.COMMANDS)

    def test_model_lookup(self):
        self.assertEqual(parallax.model(user_with({}, model="R2"), "V"), "R2")


if __name__ == "__main__":
    unittest.main()
