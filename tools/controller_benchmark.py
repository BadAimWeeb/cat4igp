#!/usr/bin/env python3
"""Read-only controller load and externally induced recovery measurements.

Examples (use an isolated staging controller and a short-lived admin session):
  CAT4IGP_BENCH_COOKIE='__Host-cat4igp=...' python3 tools/controller_benchmark.py load --url https://controller.example --confirm-staging --duration 60 --rate 10 --concurrency 4
  CAT4IGP_BENCH_COOKIE='__Host-cat4igp=...' python3 tools/controller_benchmark.py recovery --url https://controller.example --confirm-staging --observation-window 120

Recovery never injects a failure: after the baseline message, an operator may
interrupt and restore the isolated controller. Do not run against production.
The cookie is sent only to the supplied origin and never printed.
"""
import argparse
import collections
import concurrent.futures
import http.client
import json
import math
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse

PATHS = ("/", "/admin/status", "/admin/inventory")


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return number


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[math.ceil(fraction * len(ordered)) - 1]


def request(origin, path, cookie, timeout):
    start = time.monotonic()
    conn = None
    try:
        cls = http.client.HTTPSConnection if origin.scheme == "https" else http.client.HTTPConnection
        conn = cls(origin.hostname, origin.port, timeout=timeout)
        headers = {"Accept": "application/json"}
        if cookie and path.startswith("/admin/"):
            headers["Cookie"] = cookie
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        while response.read(65536):
            pass
        return response.status, time.monotonic() - start
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout):
        return 0, time.monotonic() - start
    finally:
        if conn is not None:
            conn.close()


def load(args, origin, cookie):
    start = time.monotonic()
    deadline = start + args.duration
    lock = threading.Lock()
    next_slot = start
    results = []

    def worker():
        nonlocal next_slot
        local = []
        while True:
            with lock:
                slot = max(next_slot, time.monotonic())
                next_slot = slot + 1 / args.rate
            if slot >= deadline:
                break
            delay = slot - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            if time.monotonic() >= deadline:
                break
            status, latency = request(origin, args.path, cookie, args.timeout)
            local.append((status, latency))
        return local

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for part in pool.map(lambda _: worker(), range(args.concurrency)):
            results.extend(part)
    elapsed = time.monotonic() - start
    successes = [latency for status, latency in results if status == 200]
    failures = len(results) - len(successes)
    p95 = percentile(successes, 0.95)
    error_rate = failures / len(results) if results else 1.0
    offered_requests = max(1, math.ceil(args.duration * args.rate))
    completion_ratio = len(results) / offered_requests
    passed = bool(results) and error_rate <= args.max_error_rate and p95 is not None and p95 <= args.max_p95_ms / 1000 and completion_ratio >= args.min_completion_ratio
    report = {"mode": "load", "path": args.path, "elapsed_seconds": round(elapsed, 3),
              "scheduled_rate_per_second": args.rate, "completed_per_second": round(len(results) / elapsed, 3),
              "requests": len(results), "offered_requests": offered_requests, "completion_ratio": round(completion_ratio, 6), "statuses": dict(sorted(collections.Counter(str(s) if s else "transport_error" for s, _ in results).items())),
              "error_rate": round(error_rate, 6), "latency_ms": {"p50": ms(percentile(successes, 0.5)), "p95": ms(p95), "p99": ms(percentile(successes, 0.99)), "max": ms(max(successes) if successes else None)},
              "thresholds": {"max_error_rate": args.max_error_rate, "max_p95_ms": args.max_p95_ms, "min_completion_ratio": args.min_completion_ratio}, "passed": passed}
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


def ms(value):
    return round(value * 1000, 3) if value is not None else None


def recovery(args, origin, cookie):
    status, latency = request(origin, args.path, cookie, args.timeout)
    if status != 200:
        print(json.dumps({"mode": "recovery", "passed": False, "reason": "baseline request failed", "status": status or "transport_error"}))
        return 1
    print("Baseline healthy. Induce and restore a failure on the isolated staging controller now; observing...", file=sys.stderr, flush=True)
    deadline = time.monotonic() + args.observation_window
    first_failure = last_failure = first_success = None
    streak = probes = 0
    counts = collections.Counter()
    while time.monotonic() < deadline:
        started = time.monotonic()
        status, latency = request(origin, args.path, cookie, min(args.timeout, max(0.001, deadline - started)))
        now = time.monotonic()
        probes += 1
        counts[str(status) if status else "transport_error"] += 1
        if status != 200:
            first_failure = first_failure if first_failure is not None else started
            last_failure = now
            first_success = None
            streak = 0
        elif first_failure is not None:
            if streak == 0:
                first_success = now
            streak += 1
            if streak >= args.success_streak:
                break
        time.sleep(max(0, min(args.interval - (time.monotonic() - started), deadline - time.monotonic())))
    confirmed = streak >= args.success_streak
    outage = first_success - first_failure if confirmed else None
    passed = confirmed and outage <= args.max_recovery_seconds
    report = {"mode": "recovery", "path": args.path, "probes": probes, "statuses": dict(counts),
              "failure_observed": first_failure is not None, "recovery_confirmed": confirmed,
              "observed_outage_seconds": round(outage, 3) if outage is not None else None,
              "last_failure_to_first_success_seconds": round(first_success - last_failure, 3) if confirmed else None,
              "success_streak": streak, "thresholds": {"max_recovery_seconds": args.max_recovery_seconds, "required_success_streak": args.success_streak}, "passed": passed}
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("load", "recovery"):
        p = sub.add_parser(mode)
        p.add_argument("--url", required=True, help="staging controller origin, HTTPS except localhost")
        p.add_argument("--confirm-staging", action="store_true", required=True, help="confirm target is isolated staging")
        p.add_argument("--path", choices=PATHS, default="/admin/status", help="read-only endpoint; admin paths require CAT4IGP_BENCH_COOKIE")
        p.add_argument("--timeout", type=positive, default=5.0, help="per-request timeout in seconds (default: 5)")
    p = sub.choices["load"]
    p.add_argument("--duration", type=positive, default=60, help="load duration in seconds, max 3600")
    p.add_argument("--min-completion-ratio", type=float, default=0.9, help="minimum fraction of offered requests completed (default: 0.9)")
    p.add_argument("--rate", type=positive, default=5, help="aggregate maximum request starts/second, max 100")
    p.add_argument("--concurrency", type=int, default=4, help="worker count, 1–32")
    p.add_argument("--max-error-rate", type=float, default=0.01, help="maximum failed fraction (default: 0.01)")
    p.add_argument("--max-p95-ms", type=positive, default=1000, help="maximum successful request p95 (default: 1000 ms)")
    p = sub.choices["recovery"]
    p.add_argument("--observation-window", type=positive, default=120, help="maximum observation seconds, max 3600")
    p.add_argument("--interval", type=positive, default=1, help="probe interval seconds")
    p.add_argument("--success-streak", type=int, default=3, help="consecutive 200 responses required")
    p.add_argument("--max-recovery-seconds", type=positive, default=30, help="maximum observed outage (default: 30 seconds)")
    args = parser.parse_args()
    try:
        origin = urllib.parse.urlsplit(args.url)
        port = origin.port
        if origin.scheme not in ("http", "https") or not origin.hostname or origin.username is not None or origin.password is not None or origin.path not in ("", "/") or origin.query or origin.fragment or (port is not None and port == 0):
            raise ValueError()
        if origin.scheme == "http" and origin.hostname not in ("localhost", "127.0.0.1", "::1"):
            parser.error("HTTP is allowed only on loopback; use HTTPS elsewhere")
    except ValueError:
        parser.error("--url must be an HTTP(S) origin without credentials, path, query or fragment")
    cookie = os.environ.get("CAT4IGP_BENCH_COOKIE", "")
    if args.path.startswith("/admin/") and (not cookie.startswith("__Host-cat4igp=") or not cookie[len("__Host-cat4igp="):] or any(c in cookie for c in "\r\n;")):
        parser.error("set CAT4IGP_BENCH_COOKIE to the single __Host-cat4igp session cookie")
    if args.mode == "load":
        if args.duration > 3600 or args.rate > 100 or not 1 <= args.concurrency <= 32 or not 0 <= args.max_error_rate <= 1 or not 0 <= args.min_completion_ratio <= 1:
            parser.error("load limits: duration <= 3600, rate <= 100, concurrency 1–32, error and completion ratios 0–1")
        return load(args, origin, cookie)
    if args.observation_window > 3600 or not 1 <= args.success_streak <= 100:
        parser.error("recovery limits: observation window <= 3600, success streak 1–100")
    return recovery(args, origin, cookie)


if __name__ == "__main__":
    sys.exit(main())
