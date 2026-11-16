#!/usr/bin/env python3
import argparse
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

import healthcheck


class HealthCheckTests(unittest.TestCase):
    def check(self, responses, *args):
        with patch.object(sys, "argv", ["healthcheck.py", *args]), patch.object(healthcheck, "run", side_effect=responses), contextlib.redirect_stdout(io.StringIO()) as output:
            result = healthcheck.main()
        return result, output.getvalue()

    def test_healthy_with_tunnel_probe(self):
        status = "Running: Yes\nServer Configured: Yes\nNode Key Present: Yes\nController Snapshot Age Seconds: 120\n"
        result, output = self.check([(0, status, ""), (0, "", "")], "--probe", "wg0=192.0.2.1")
        self.assertEqual(result, 0)
        self.assertIn("controller snapshot age 120s", output)

    def test_failure_and_unknown(self):
        status = "Running: Yes\nServer Configured: Yes\nNode Key Present: Yes\nController Snapshot Age Seconds: 10\nMessage: snapshot failed\n"
        self.assertEqual(self.check([(0, status, ""), (1, "", "")], "--probe", "wg0=192.0.2.1")[0], 2)
        self.assertEqual(self.check([(0, status.replace("Message: snapshot failed\n", ""), "")])[0], 3)
        self.assertEqual(self.check([(0, "unexpected", "")])[0], 3)
        self.assertEqual(self.check([(None, "", "timeout")])[0], 3)

    def test_controller_freshness(self):
        prefix = "Running: Yes\nServer Configured: Yes\nNode Key Present: Yes\n"
        probe = (0, "", "")
        for age, expected in [("Unknown", 2), ("121", 2), ("120", 0), ("0", 0), ("-1", 3), ("1.5", 3), ("NaN", 3), ("９", 3)]:
            with self.subTest(age=age):
                self.assertEqual(self.check([(0, prefix + f"Controller Snapshot Age Seconds: {age}\n", ""), probe], "--probe", "wg0=192.0.2.1")[0], expected)
        self.assertEqual(self.check([(0, prefix, "")])[0], 3)
        self.assertEqual(self.check([(0, prefix + "Controller Snapshot Age Seconds: 11\n", ""), probe], "--probe", "wg0=192.0.2.1", "--max-controller-age", "10")[0], 2)
        duplicate = prefix + "Controller Snapshot Age Seconds: 1\nController Snapshot Age Seconds: 2\n"
        self.assertEqual(self.check([(0, duplicate, "")])[0], 3)
        with self.assertRaises(SystemExit):
            self.check([], "--max-controller-age", "0")

    def test_invalid_probe(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            healthcheck.probe_spec("wg0=not-an-address")

    def test_command_line_executes_client_and_bound_probe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = root / "client"
            client.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALLS/client.args\"\nprintf 'Running: Yes\\nServer Configured: Yes\\nNode Key Present: Yes\\nController Snapshot Age Seconds: 5\\n'\n")
            ping = root / "ping"
            ping.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CALLS/ping.args\"\nexit \"${PING_EXIT:-0}\"\n")
            client.chmod(0o700)
            ping.chmod(0o700)
            env = {**os.environ, "PATH": str(root), "CALLS": str(root)}
            command = [sys.executable, str(Path(healthcheck.__file__)), "--client", str(client),
                       "--config", "config with spaces.toml", "--probe", "wg0=192.0.2.1", "--timeout", "3"]
            result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / "client.args").read_text().splitlines(), ["--config", "config with spaces.toml", "status"])
            self.assertEqual((root / "ping.args").read_text().splitlines(), ["-n", "-I", "wg0", "-c", "1", "-W", "2", "192.0.2.1"])
            result = subprocess.run(command, capture_output=True, text=True, env={**env, "PING_EXIT": "1"}, timeout=10)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("tunnel probe failed wg0=192.0.2.1", result.stdout)


if __name__ == "__main__":
    unittest.main()
