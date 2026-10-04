"""Offline tests. Known synthetic token only; never invokes Wrangler or a network."""
import importlib.util
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import time
import unittest
from unittest import mock
import warnings

PATH = Path(__file__).with_name("deploy-probe-private.py")
spec = importlib.util.spec_from_file_location("private_deploy", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
FAKE = "synthetic_token_for_offline_tests_only"


class PrivateDeploymentTests(unittest.TestCase):
    def test_configuration_and_environment_are_bounded(self):
        module.checked_config()
        inherited = {"PATH": "/usr/bin", "HOME": "/tmp", "NODE_OPTIONS": "unsafe",
                     "CLOUDFLARE_API_BASE_URL": "https://example.invalid", "UNRELATED_SECRET": "fixture"}
        env = module.child_environment("a" * 32, FAKE, inherited)
        self.assertNotIn("NODE_OPTIONS", env)
        self.assertNotIn("CLOUDFLARE_API_BASE_URL", env)
        self.assertNotIn("UNRELATED_SECRET", env)
        for key in ("WRANGLER_WRITE_LOGS", "WRANGLER_SEND_METRICS", "WRANGLER_SEND_ERROR_REPORTS"):
            self.assertEqual(env[key], "false")
        self.assertEqual(env["WRANGLER_LOG_SANITIZE"], "true")

    def test_subprocess_has_no_token_argument_or_output_and_env_is_cleared(self):
        observed = {}
        def fake_runner(command, **options):
            self.assertNotIn(FAKE, " ".join(command))
            self.assertEqual(command[-5:], ["deploy", "--config", str(module.CONFIG), "--env-file", os.devnull])
            self.assertEqual(options["env"]["CLOUDFLARE_API_TOKEN"], FAKE)
            for stream in ("stdin", "stdout", "stderr"):
                self.assertEqual(options[stream], subprocess.DEVNULL)
            observed["env"] = options["env"]
            return subprocess.CompletedProcess(command, 0)
        self.assertEqual(module.deploy("a" * 32, FAKE, "/fake/node", fake_runner), 0)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", observed["env"])

    def test_token_environment_is_cleared_on_runner_failure(self):
        observed = {}
        def failing_runner(command, **options):
            observed["env"] = options["env"]
            raise subprocess.TimeoutExpired(command, 180)
        with self.assertRaises(subprocess.TimeoutExpired):
            module.deploy("a" * 32, FAKE, "/fake/node", failing_runner)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", observed["env"])

    def test_non_terminal_input_stops_before_reading(self):
        with mock.patch.object(module.sys.stdin, "isatty", return_value=False), mock.patch.object(module.getpass, "getpass") as read:
            with self.assertRaises(ValueError):
                module.hidden_token()
            read.assert_not_called()

    def test_getpass_echo_fallback_is_forbidden(self):
        def no_echo_unavailable(*args):
            warnings.warn("synthetic echo failure", module.getpass.GetPassWarning)
            self.fail("getpass fallback must stop before reading")
        with mock.patch.object(module.sys.stdin, "isatty", return_value=True), mock.patch.object(module.sys.stderr, "isatty", return_value=True), mock.patch.object(module.getpass, "getpass", side_effect=no_echo_unavailable):
            with self.assertRaisesRegex(ValueError, "saisie masquée est indisponible"):
                module.hidden_token()

    def test_hidden_terminal_input_never_echoes_synthetic_secret(self):
        # A real PTY is needed to verify that getpass disables echo. The child
        # calls only hidden_token(), and cannot reach the deployment function.
        master, slave = pty.openpty()
        source = ("import importlib.util; "
                  "s=importlib.util.spec_from_file_location('p', " + repr(str(PATH)) + "); "
                  "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                  "t=m.hidden_token(); print('INPUT_ACCEPTED')")
        process = subprocess.Popen([sys.executable, "-c", source], stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        output = b""
        try:
            deadline = time.monotonic() + 5
            while b"masqu" not in output and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    output += os.read(master, 4096)
            self.assertIn(b"masqu", output)
            os.write(master, FAKE.encode() + b"\n")
            while process.poll() is None and time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        output += os.read(master, 4096)
                    except OSError:
                        break
            process.wait(timeout=2)
            self.assertEqual(process.returncode, 0)
            self.assertIn(b"INPUT_ACCEPTED", output)
            self.assertNotIn(FAKE.encode(), output)
        finally:
            if process.poll() is None:
                process.kill()
            os.close(master)


if __name__ == "__main__":
    unittest.main()
