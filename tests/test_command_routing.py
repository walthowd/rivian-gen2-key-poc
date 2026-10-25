"""Offline tests of cmd_command's legacy/parallax routing; no account access."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rivian_key

KEY = {"name": "k", "vehicle_id": "V", "phone_id": "P", "identity_id": "I",
       "vehicle_public_key": "04", "private_key": "pk"}


def user(flags):
    feats = [{"name": k, "status": v} for k, v in flags.items()]
    return {"vehicles": [{"id": "V", "vehicle": {"model": "R1S",
                                                 "vehicleState": {"supportedFeatures": feats}}}]}


class Routing(unittest.IsolatedAsyncioTestCase):
    async def run_command(self, flags, **args):
        api = MagicMock()
        api.send_vehicle_command = AsyncMock(return_value="cmd-id")
        api.get_vehicle_command_state = AsyncMock()
        api.close = AsyncMock()
        with patch.multiple(rivian_key, load_key=MagicMock(return_value=KEY),
                            connect=AsyncMock(return_value=api),
                            current_user=AsyncMock(return_value=user(flags)),
                            derive_secret=MagicMock(return_value=b"s")), \
                patch.object(rivian_key.halloween, "send", AsyncMock(return_value=True)) as send:
            # setup's guided test passes only these attributes (no parallax/legacy/features)
            ns = SimpleNamespace(key=None, value=None, list=False, **args)
            result = await rivian_key.cmd_command(ns)
        return result, api, send

    async def test_setup_namespace_without_flags_goes_legacy(self):
        _, api, send = await self.run_command({}, command="lock")
        api.send_vehicle_command.assert_awaited_once()
        send.assert_not_awaited()

    async def test_available_category_goes_parallax(self):
        _, api, send = await self.run_command({"PVS_BD_CMD": "AVAILABLE"}, command="lock")
        send.assert_awaited_once()
        self.assertEqual(send.await_args.args[3], "body.locks.lock")
        api.send_vehicle_command.assert_not_awaited()

    async def test_legacy_flag_overrides(self):
        _, api, send = await self.run_command({"PVS_BD_CMD": "AVAILABLE"}, command="lock", legacy=True)
        api.send_vehicle_command.assert_awaited_once()
        send.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
