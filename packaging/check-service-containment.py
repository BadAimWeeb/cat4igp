#!/usr/bin/env python3
"""Check packaged systemd descendant containment in a disposable Linux VM.

sudo python3 packaging/check-service-containment.py --confirm-disposable
Add --main-crash to SIGKILL only the main process and verify manager cleanup.
--main-crash disables restart to observe failure cleanup. --restart-crash uses
the packaged Restart/RestartSec and checks a new process/runtime generation.
Requires root, Python 3, systemd-run and a running systemd system manager.
Creates only a unique transient service and an owner-only temporary directory.
This checks packaged systemd process/runtime cleanup, not unmanaged backend cleanup.
"""
import argparse
import configparser
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid


def command(*args, check=True, timeout=25):
    return subprocess.run(args, check=check, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-disposable', action='store_true', required=True)
    scenario_flags = parser.add_mutually_exclusive_group()
    scenario_flags.add_argument('--main-crash', action='store_true',
                        help='kill the service main process instead of requesting stop')
    scenario_flags.add_argument('--restart-crash', action='store_true',
                                help='verify actual packaged restart and fresh runtime generation')
    options = parser.parse_args()
    assert __debug__, 'assertions must be enabled'
    assert os.geteuid() == 0, 'root in a disposable systemd VM required'
    unit_file = Path(__file__).with_name('cat4igp-client.service')
    config = configparser.ConfigParser(interpolation=None, strict=True)
    with unit_file.open() as source:
        config.read_file(source)
    properties = {key: config['Service'][key] for key in
                  ('KillMode', 'SendSIGKILL', 'TimeoutStopSec', 'RuntimeDirectory', 'RuntimeDirectoryMode')}
    assert properties['KillMode'] == 'control-group'
    assert properties['SendSIGKILL'] == 'yes'
    assert properties['TimeoutStopSec'] == '15s'
    assert properties['RuntimeDirectory'] == 'cat4igp-client'
    assert properties['RuntimeDirectoryMode'] == '0700'
    if options.restart_crash:
        properties.update({key: config['Service'][key] for key in ('Restart', 'RestartSec')})
        assert properties['Restart'] == 'on-failure' and properties['RestartSec'] == '5'
    runtime = Path('/run') / properties['RuntimeDirectory']
    assert not os.path.lexists(runtime), 'runtime directory already exists; do not disturb an installed service'
    unit = 'cat4igp-containment-' + uuid.uuid4().hex + '.service'
    child_pid = None
    # The helper enters another session and ignores TERM before publishing its PID.
    # Its parent retains the service's original session and remains alive.
    helper = '''import os, signal, sys, time, uuid
generation = uuid.uuid4().hex
pid = os.fork()
if pid == 0:
    os.setsid()
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    runtime = os.environ['RUNTIME_DIRECTORY']
    if runtime != '/run/cat4igp-client' or (os.stat(runtime).st_mode & 0o7777) != 0o700:
        raise RuntimeError('unexpected managed runtime directory')
    with open(os.path.join(runtime, 'proof-sentinel'), 'x') as sentinel:
        sentinel.write(generation)
    temporary = sys.argv[1] + '.' + generation
    with open(temporary, "x") as output:
        output.write(str(os.getpid()) + ' ' + generation)
    os.replace(temporary, sys.argv[1])
    while True:
        time.sleep(1)
while True:
    time.sleep(1)
'''
    with tempfile.TemporaryDirectory(prefix='cat4igp-containment-') as directory:
        pidfile = Path(directory) / 'child.pid'
        try:
            args = ['systemd-run', '--unit=' + unit]
            for key, value in properties.items():
                args.extend(['--property', key + '=' + value])
            # Failure-only proof disables restart; restart-crash uses packaged values.
            if not options.restart_crash:
                args.extend(['--property', 'Restart=no'])
            args.extend([sys.executable, '-c', helper, str(pidfile)])
            command(*args)
            deadline = time.monotonic() + 10
            while not pidfile.exists():
                assert time.monotonic() < deadline, 'helper startup timed out'
                time.sleep(0.05)
            child_text, generation = pidfile.read_text().split()
            child_pid = int(child_text)
            stat = Path(f'/proc/{child_pid}/stat')
            identity = stat.read_text().rsplit(')', 1)[1].split()[19]
            assert (runtime / 'proof-sentinel').read_text() == generation
            if options.main_crash or options.restart_crash:
                main_pid = int(command('systemctl', 'show', '--property=MainPID', '--value', unit).stdout)
                assert main_pid > 1 and main_pid != child_pid
                # Ask systemd to signal its owned main process, not a numeric PID.
                command('systemctl', 'kill', '--kill-whom=main', '--signal=KILL', unit)
            else:
                command('systemctl', 'stop', unit)
            deadline = time.monotonic() + 30
            while True:
                try:
                    fields = stat.read_text().rsplit(')', 1)[1].split()
                    live = fields[19] == identity and fields[0] not in ('Z', 'X', 'x')
                except FileNotFoundError:
                    live = False
                runtime_ready = not os.path.lexists(runtime)
                if options.restart_crash:
                    try:
                        next_child, next_generation = pidfile.read_text().split()
                        next_main = int(command('systemctl', 'show', '--property=MainPID', '--value', unit).stdout)
                        runtime_ready = (next_generation != generation and next_main > 1
                            and next_main != main_pid and int(next_child) != child_pid
                            and (runtime / 'proof-sentinel').read_text() == next_generation)
                    except FileNotFoundError:
                        runtime_ready = False
                if not live and runtime_ready:
                    break
                assert time.monotonic() < deadline, 'descendant or managed runtime survived service shutdown'
                time.sleep(0.05)
            if options.restart_crash:
                command('systemctl', 'stop', unit)
            assert not os.path.lexists(runtime), 'systemd runtime directory survived service stop'
            if options.main_crash:
                assert command('systemctl', 'show', '--property=Result', '--value', unit).stdout.strip() == 'signal'
            scenario = ('crash/restart with fresh runtime' if options.restart_crash else
                        'main-process SIGKILL' if options.main_crash else 'explicit stop')
            print(f'PASS: {scenario} terminates escaped descendant and removes managed runtime secrets')
        finally:
            # Address only the unique service cgroup, never a possibly reused PID.
            for args, timeout in [
                (('systemctl', 'kill', '--kill-whom=all', '--signal=KILL', unit), 5),
                (('systemctl', 'stop', unit), 25),
                (('systemctl', 'reset-failed', unit), 5),
            ]:
                try:
                    command(*args, check=False, timeout=timeout)
                except subprocess.TimeoutExpired:
                    pass


if __name__ == '__main__':
    main()
