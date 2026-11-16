#!/usr/bin/env python3
"""Nagios-compatible local daemon and tunnel-path checks; run --help for usage."""
import argparse
import ipaddress
import subprocess
import sys


def run(args, timeout):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired) as error:
        return None, "", str(error)


def probe_spec(value):
    interface, separator, address = value.partition("=")
    if not separator or not interface or len(interface.encode()) > 15 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for c in interface):
        raise argparse.ArgumentTypeError("expected Linux INTERFACE=IP_ADDRESS")
    try:
        return interface, str(ipaddress.ip_address(address))
    except ValueError as error:
        raise argparse.ArgumentTypeError("probe address must be an IP address") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog="Run on the client host with permission to access its daemon socket. Probe addresses must answer ICMP over the specified tunnel. Exit: 0 OK, 2 critical, 3 unknown.")
    parser.add_argument("--client", default="cat4igp-client", help="client executable")
    parser.add_argument("--config", default="/etc/cat4igp/client.toml")
    parser.add_argument("--probe", action="append", type=probe_spec, default=[], metavar="INTERFACE=IP", help="required tunnel-path probe; repeat for each path")
    parser.add_argument("--timeout", type=int, default=10, help="per-command timeout in seconds (default: 10)")
    parser.add_argument("--max-controller-age", type=int, default=120, metavar="SECONDS", help="maximum age of a verified controller snapshot pull (default: 120 seconds)")
    args = parser.parse_args()
    if args.timeout < 2:
        parser.error("--timeout must be at least 2 seconds")
    if args.max_controller_age < 1:
        parser.error("--max-controller-age must be at least 1 second")
    code, out, err = run([args.client, "--config", args.config, "status"], args.timeout)
    if code is None:
        print(f"UNKNOWN - cannot execute client status: {err}")
        return 3
    if code != 0:
        print(f"CRITICAL - client status failed: {err.strip() or out.strip() or code}")
        return 2
    fields = {}
    for line in out.splitlines():
        key, separator, value = line.strip().partition(":")
        if separator:
            if key in fields:
                print("UNKNOWN - duplicate client status field")
                return 3
            fields[key] = value.strip()
    required = ("Running", "Server Configured", "Node Key Present")
    if any(fields.get(key) not in ("Yes", "No") for key in required):
        print("UNKNOWN - unrecognized client status output")
        return 3
    problems = [f"{key}: {fields[key]}" for key in required if fields[key] != "Yes"]
    age = fields.get("Controller Snapshot Age Seconds")
    if age == "Unknown":
        problems.append("no verified controller snapshot pull since daemon start")
    elif age is None or not age.isascii() or not age.isdecimal() or len(age) > 20:
        print("UNKNOWN - unrecognized controller snapshot age in client status")
        return 3
    elif int(age) > args.max_controller_age:
        problems.append(f"controller snapshot age {age}s exceeds {args.max_controller_age}s")
    if fields.get("Message"):
        problems.append("daemon: " + fields["Message"])
    for interface, address in args.probe:
        code, _, error = run(["ping", "-n", "-I", interface, "-c", "1", "-W", str(args.timeout - 1), address], args.timeout)
        if code is None:
            print(f"UNKNOWN - cannot execute tunnel probe {interface}={address}: {error}")
            return 3
        if code != 0:
            problems.append(f"tunnel probe failed {interface}={address}")
    if problems:
        print("CRITICAL - " + "; ".join(problems))
        return 2
    if not args.probe:
        print("UNKNOWN - daemon reports no error, but no tunnel paths were probed")
        return 3
    print(f"OK - controller snapshot age {age}s; daemon reports no error; {len(args.probe)} tunnel path(s) respond")
    return 0


if __name__ == "__main__":
    sys.exit(main())
