#!/usr/bin/env python3
"""Run with: python3 -m unittest discover -s tools -p 'test_controller_benchmark.py'"""
import contextlib
import io
import json
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from unittest.mock import patch

import controller_benchmark as bench


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/admin/status" and self.headers.get("Cookie") == "__Host-cat4igp=test" else 503)
        self.end_headers()
        self.wfile.write(b"response")

    def log_message(self, *args):
        pass


class BenchmarkCheck(unittest.TestCase):
    def test_percentile(self):
        self.assertIsNone(bench.percentile([], .95))
        self.assertEqual(bench.percentile([3, 1, 2], .95), 3)
        self.assertEqual(bench.percentile([3, 1, 2], .5), 2)

    def test_real_read_only_request(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = urllib.parse.urlsplit(f"http://127.0.0.1:{server.server_port}")
            self.assertEqual(bench.request(origin, "/admin/status", "__Host-cat4igp=test", 1)[0], 200)
            self.assertEqual(bench.request(origin, "/", "__Host-cat4igp=test", 1)[0], 503)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_recovery_requires_failure_and_stable_success(self):
        args = SimpleNamespace(path="/admin/status", timeout=1, observation_window=10, interval=.01, success_streak=2, max_recovery_seconds=2)
        responses = iter([(200, 0), (503, 0), (200, 0), (503, 0), (200, 0), (200, 0)])
        output = io.StringIO()
        with patch.object(bench, "request", side_effect=lambda *args: next(responses)), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(bench.recovery(args, None, ""), 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["failure_observed"])
        self.assertTrue(report["recovery_confirmed"])
        self.assertEqual(report["statuses"], {"200": 3, "503": 2})
        self.assertEqual(report["success_streak"], 2)

    def test_recovery_rejects_failed_baseline(self):
        args = SimpleNamespace(path="/admin/status", timeout=1)
        output = io.StringIO()
        with patch.object(bench, "request", return_value=(503, 0)), contextlib.redirect_stdout(output):
            self.assertEqual(bench.recovery(args, None, ""), 1)
        self.assertFalse(json.loads(output.getvalue())["passed"])

    def test_load_rejects_failed_requests(self):
        args = SimpleNamespace(path="/admin/status", timeout=1, duration=.02, rate=100,
                               concurrency=1, max_error_rate=0, max_p95_ms=1000,
                               min_completion_ratio=0)
        output = io.StringIO()
        with patch.object(bench, "request", return_value=(503, 0)), contextlib.redirect_stdout(output):
            self.assertEqual(bench.load(args, None, ""), 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report["passed"])
        self.assertGreater(report["requests"], 0)

    def test_load_tiny_positive_values_do_not_divide_by_zero(self):
        args = SimpleNamespace(path="/", timeout=1, duration=1e-300, rate=1e-300,
                               concurrency=1, max_error_rate=0, max_p95_ms=1000,
                               min_completion_ratio=0)
        output = io.StringIO()
        with patch.object(bench.time, "monotonic", side_effect=[0, 1, 1]), contextlib.redirect_stdout(output):
            self.assertEqual(bench.load(args, None, ""), 1)
        report = json.loads(output.getvalue())
        self.assertEqual(report["offered_requests"], 1)
        self.assertEqual(report["completion_ratio"], 0)


if __name__ == "__main__":
    unittest.main()
