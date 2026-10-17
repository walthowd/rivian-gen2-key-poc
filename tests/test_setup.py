"""Offline tests of setup decisions; no account or Bluetooth access."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rivian_key


READY = {"isPaired": True, "isEnabled": True}
UNPAIRED = {"isPaired": False, "isEnabled": True}


class GuidedSetup(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.args = SimpleNamespace(key=None, vehicle=None, token=False)
        replacements = {
            "SESSION_FILE": Mock(),
            "load_session": Mock(return_value={"user_session_token": "fake"}),
            "key_names": Mock(return_value=["Test key"]),
            "load_key": Mock(return_value={"name": "Test key"}),
            "cmd_login": AsyncMock(),
            "cmd_enroll": AsyncMock(),
            "cmd_status": AsyncMock(return_value=READY),
            "cmd_command": AsyncMock(return_value=True),
            "log": Mock(file=None),
        }
        for name, replacement in replacements.items():
            patcher = patch.object(rivian_key, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
            setattr(self, name, replacement)
        self.stdin = self.enterContext(patch.object(sys.stdin, "isatty", return_value=True))
        self.inputs = self.enterContext(patch("builtins.input", return_value="0"))
        self.enterContext(patch("builtins.print"))
        self.pair = self.enterContext(patch.object(rivian_key.subprocess, "run",
                                                  return_value=SimpleNamespace(returncode=0)))
        self.sleep = self.enterContext(patch.object(rivian_key.asyncio, "sleep", new_callable=AsyncMock))

    async def test_first_run_logs_in_enrolls_pairs_and_verifies(self):
        self.SESSION_FILE.exists.return_value = False
        self.key_names.return_value = []
        self.inputs.side_effect = ["New key", "yes", "0"]
        self.cmd_status.side_effect = [UNPAIRED, UNPAIRED, READY]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.cmd_login.assert_awaited_once()
        self.assertEqual(self.cmd_enroll.await_args.args[0].name, "New key")
        self.assertEqual(self.pair.call_args.args[0][-2:], ["--key", "New key"])
        self.sleep.assert_awaited_once_with(10)
        self.cmd_command.assert_not_awaited()

    async def test_ready_key_skips_setup_steps(self):
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.cmd_login.assert_not_awaited()
        self.cmd_enroll.assert_not_awaited()
        self.pair.assert_not_called()

    async def test_missing_token_prompts_login(self):
        self.load_session.return_value = {}
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.cmd_login.assert_awaited_once()

    async def test_declining_pairing_preserves_state(self):
        self.cmd_status.return_value = UNPAIRED
        self.inputs.return_value = "n"
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.pair.assert_not_called()
        self.cmd_command.assert_not_awaited()

    async def test_pair_failure_can_retry(self):
        self.cmd_status.side_effect = [UNPAIRED, UNPAIRED, READY]
        self.pair.side_effect = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]
        self.inputs.side_effect = ["y", "y", "0"]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.assertEqual(self.pair.call_count, 2)

    async def test_failed_pair_reports_failure_without_commands(self):
        self.cmd_status.return_value = UNPAIRED
        self.pair.return_value.returncode = 1
        self.inputs.side_effect = ["y", "n"]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 1)
        self.cmd_command.assert_not_awaited()
        self.assertIn(call(f"Report an issue with those logs and your vehicle/OS versions: "
                           f"{rivian_key.ISSUES_URL}"), self.log.call_args_list)

    async def test_cloud_delay_does_not_claim_success(self):
        self.cmd_status.return_value = UNPAIRED
        self.inputs.return_value = "y"
        self.assertEqual(await rivian_key.cmd_setup(self.args), 1)
        self.assertEqual(self.sleep.await_count, 6)
        self.cmd_command.assert_not_awaited()

    async def test_disabled_key_does_not_pair_or_offer_tests(self):
        self.cmd_status.return_value = {"isPaired": True, "isEnabled": False}
        self.assertEqual(await rivian_key.cmd_setup(self.args), 1)
        self.pair.assert_not_called()
        self.cmd_command.assert_not_awaited()

    async def test_unregistered_key_is_set_aside_and_replaced(self):
        stale = Mock()
        stale.name = "Test key.json"
        self.enterContext(patch.object(rivian_key, "key_path", return_value=stale))
        self.cmd_status.side_effect = [None, READY]
        self.inputs.side_effect = ["", "0"]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        stale.rename.assert_called_once()
        self.assertEqual(self.cmd_enroll.await_args.args[0].name, "Test key")

    async def test_new_key_never_listed_reports_failure(self):
        self.key_names.return_value = []
        self.inputs.side_effect = ["New key"]
        self.cmd_status.return_value = None
        self.assertEqual(await rivian_key.cmd_setup(self.args), 1)
        self.pair.assert_not_called()

    async def test_select_existing_key_and_test_command(self):
        self.key_names.return_value = ["First", "Second"]
        self.inputs.side_effect = ["invalid", "2", "3", "0"]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        command_args = self.cmd_command.await_args.args[0]
        self.assertEqual((command_args.key, command_args.command), ("Second", "unlock"))

    async def test_failed_test_command_does_not_end_setup(self):
        self.cmd_command.side_effect = [RuntimeError("boom"), True]
        self.inputs.side_effect = ["6", "1", "0"]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.assertEqual(self.cmd_command.await_count, 2)

    async def test_new_key_waits_until_vehicle_lists_it(self):
        self.key_names.return_value = []
        self.inputs.side_effect = ["New key", "0"]
        self.cmd_status.side_effect = [None, None, READY]
        self.assertEqual(await rivian_key.cmd_setup(self.args), 0)
        self.assertEqual(self.sleep.await_count, 2)

    async def test_noninteractive_setup_exits_before_account_access(self):
        self.stdin.return_value = False
        with self.assertRaises(SystemExit):
            await rivian_key.cmd_setup(self.args)
        self.load_session.assert_not_called()
        self.cmd_login.assert_not_awaited()


class SetupCLI(unittest.TestCase):
    def test_default_and_explicit_setup_dispatch_and_exit_status(self):
        for argv in ([], ["setup", "--key", "Test key"]):
            with self.subTest(argv=argv), \
                    patch.object(rivian_key, "KEYS_DIR"), \
                    patch.object(rivian_key, "log"), \
                    patch.object(rivian_key, "cmd_setup", new_callable=AsyncMock) as setup:
                setup.return_value = 1
                self.assertEqual(rivian_key.main(argv), 1)
                self.assertEqual(setup.await_args.args[0].cmd, "setup")
                self.assertEqual(setup.await_args.args[0].key, "Test key" if argv else None)

    def test_setup_validation_errors_include_log_and_issue_guidance(self):
        with patch.object(rivian_key, "KEYS_DIR"), \
                patch.object(rivian_key, "log") as logger, \
                patch.object(rivian_key, "setup_help") as help_message, \
                patch.object(rivian_key, "cmd_setup", new_callable=AsyncMock) as setup:
            logger.open.return_value = rivian_key.ROOT / "logs" / "setup-test.log"
            setup.side_effect = SystemExit(1)
            self.assertEqual(rivian_key.main([]), 1)
            help_message.assert_called_once()  # setup_help names the debug log


class ErrorText(unittest.TestCase):
    def test_graphql_codes_shown_but_not_response_data(self):
        error = RuntimeError("Error occurred", 200, {"errors": [
            {"message": "secret detail", "extensions": {"code": "CONFLICT", "reason": "BUSY"}}],
            "data": {"name": "Other Driver"}})
        with patch.object(rivian_key, "log"):
            text = rivian_key.error_text(error)
        self.assertIn("CONFLICT/BUSY", text)
        self.assertNotIn("Other Driver", text)
        self.assertNotIn("secret detail", text)


if __name__ == "__main__":
    unittest.main()
