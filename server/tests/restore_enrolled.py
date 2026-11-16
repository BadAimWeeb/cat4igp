#!/usr/bin/env python3
"""Live current-backup restore drill; run ONLY in a disposable Linux VM as root.

Prerequisites: prebuilt compatible cat4igp-server and cat4igp-client; Python 3,
OpenSSL, iproute2, util-linux (unshare), iputils-ping, wireguard-tools, kernel
WireGuard, network namespace privileges. No frontend or Internet is needed.

sudo python3 server/tests/restore_enrolled.py --confirm-disposable \
  --server /tmp/cat4igp-server --client /tmp/cat4igp-client

Use --nodes 5 for a five-daemon, dual-stack full mesh: 20 controller tunnels
and eight WireGuard interfaces per node. Every tunnel is probed in both
directions before and after restore. Endpoint roaming, offline revocation and
damaged-cache repair also support five nodes; other specialized modes remain
two-node-only. Five-node cache repair corrupts only client0's cache, preserving
its revision journal and enrollment and leaving the other four daemons running.
Measurements do not establish
80-node capacity, mixed production traffic, or an availability objective.
Add --reference-traffic-seconds 30 for eight concurrent synthetic TCP/UDP echo
streams over four mapped mesh edges spanning all five daemons and both underlay
families before backup. Payload hashes, bytes, duration and goodput are checked
and reported; this is reference traffic, not production capacity evidence.
For an actual same-version Debian reinstall, use --nodes 2 --client
/usr/bin/cat4igp-client --client-reinstall-deb /path/to/installed-version.deb.
For Arch, use --client-reinstall-arch /path/to/installed-version.pkg.tar.zst
instead; pacman and bsdtar are required. The same enrolled-state, systemd,
crash-recovery and explicit reboot phases apply; architectures must match the VM.
This runs dpkg or pacman on the disposable VM (not a filesystem sandbox), preserves both
enrolled states, and requires identical installed binary hashes. Add
--packaged-service to run scoped copies of the installed systemd unit with
drill config, namespace and state-directory overrides. No version upgrade,
default production paths, boot ordering or reboot persistence is claimed.
Add --packaged-crash-recovery to SIGKILL one scoped unit's main process and
require its packaged on-failure policy to restart it automatically. Kernel
ifindices before/after are reported rather than assumed to survive service cleanup.
For a real reboot drill, add --prepare-reboot /opt/readiness/reboot84 to the
packaged-service reinstall command. PREPARED is not PASS: reboot the VM, then
run this script with --confirm-disposable --verify-reboot /opt/readiness/reboot84.
Use --cleanup-reboot with the same directory to disable/remove only owned units
and topology. Private persisted secrets remain for explicit operator disposal.

With --reference-controller-outage, use at least 30 traffic seconds: stop the
controller during those streams, leave it stopped for five seconds, then restart
the same database and require fresh authenticated snapshots while streams run.
The subsequent backup/restore remains a separate drill.


Add --reference-soak for four continuous bidirectional probe streams over 60s,
with controller stop/restart at 20/30s before the restore drill. Reference-only
limits: 1% loss per stream, 2s missing-probe interval, 15s restart/reconciliation.

All network activity is isolated in a fresh network namespace; temporary secrets
are owner-only and deleted on exit. The JSON report contains no private keys.
The verified second snapshot copy is LOCAL, not an off-host backup. Detection,
notification, off-host transfer and key retrieval are omitted: no production
RPO/RTO compliance or older-backup recovery safety is claimed.
"""
import argparse
import contextlib
import hashlib
import http.client
import http.cookiejar
import http.server
from itertools import combinations
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from tempfile import TemporaryDirectory

from https_management import certificates, port, secret_file, stop


def run(*args):
    return subprocess.check_output([str(a) for a in args], stderr=subprocess.STDOUT, text=True)


def ping_replies(text, sent, received):
    # -O notices and ICMP errors carry sequence numbers too, but are not replies.
    sequences = [int(seq) for seq in re.findall(
        r'^(?:\[\d+(?:\.\d+)?\]\s+)?\d+ bytes from [^\n]*\bicmp_seq=(\d+)\b[^\n]*\bttl=\d+\b[^\n]*\btime[=<]',
        text, re.MULTILINE)]
    replies = set(sequences)
    assert all(1 <= seq <= sent for seq in replies), 'reference reply sequence outside transmitted range'
    assert len(sequences) == len(replies), 'duplicate reference echo replies'
    assert len(replies) == received, (
        f'reference reply accounting mismatch: parsed={len(replies)} '
        f'received={received} transmitted={sent}')
    return replies


def eventually(check, message, timeout=90):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = check()
            if value:
                return value
        except (OSError, subprocess.CalledProcessError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(0.2)

# Executed by the same Python interpreter inside a selected client namespace.
# Echo payloads are deterministic; both endpoints report checked byte hashes.
REFERENCE_TRAFFIC = r'''
import hashlib, json, socket, sys, time
role, protocol, local, remote, port, duration = sys.argv[1:]
port, duration = int(port), int(duration)
payload = bytes(range(256)) * (4 if protocol == 'udp' else 64)
kind = socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM
with socket.socket(socket.AF_INET, kind) as sock:
    sock.settimeout(duration + 10)
    sock.bind((local, port if role == 'server' else 0))
    total = packets = sent = 0
    digest = hashlib.sha256()
    started = time.monotonic()
    if role == 'server':
        if protocol == 'tcp':
            sock.listen(1)
        print('READY', flush=True)
        if protocol == 'tcp':
            conn, address = sock.accept()
            assert address[0] == remote, 'unexpected TCP source'
            with conn:
                conn.settimeout(duration + 10)
                while True:
                    data = conn.recv(65536)
                    if not data:
                        break
                    digest.update(data)
                    total += len(data)
                    conn.sendall(data)
        else:
            while True:
                try:
                    data, address = sock.recvfrom(2048)
                except socket.timeout:
                    assert total > 0, 'no UDP traffic received'
                    break
                assert address[0] == remote and data == payload, 'unexpected UDP source/payload'
                sock.settimeout(2)
                digest.update(data)
                total += len(data)
                packets += 1
                sock.sendto(data, address)
    else:
        sock.connect((remote, port))
        sock.settimeout(1)
        started = time.monotonic()
        deadline = started + duration
        while time.monotonic() < deadline:
            sent += len(payload)
            if protocol == 'tcp':
                sock.sendall(payload)
                data = bytearray()
                while len(data) < len(payload):
                    chunk = sock.recv(len(payload) - len(data))
                    assert chunk, 'truncated TCP echo'
                    data.extend(chunk)
            else:
                sock.send(payload)
                try:
                    data = sock.recv(2048)
                except socket.timeout:
                    continue
            assert data == payload, 'echo payload corruption'
            digest.update(data)
            total += len(data)
            packets += 1
    elapsed = time.monotonic() - started
    expected = hashlib.sha256()
    assert total > 0 and total % len(payload) == 0, 'incomplete payload transfer'
    for _ in range(total // len(payload)):
        expected.update(payload)
    assert digest.digest() == expected.digest(), 'transfer hash mismatch'
    print(json.dumps({'bytes': total, 'sent_bytes': sent, 'echoes': packets,
        'sha256': digest.hexdigest(), 'hash_verified': True, 'duration_seconds': elapsed,
        'goodput_bits_per_second': total * 8 / elapsed}), flush=True)
'''


class ServiceProcess:
    """The process surface used by this drill, backed by a scoped unit."""
    def __init__(self, unit):
        self.unit = unit
        assert self.pid > 0, 'packaged service lacks a running MainPID'

    @property
    def pid(self):
        return int(run('systemctl', 'show', '--value', '--property=MainPID', self.unit).strip())

    def poll(self):
        values = dict(line.split('=', 1) for line in run('systemctl', 'show',
            '--property=MainPID,ActiveState,Result', self.unit).splitlines())
        if values['ActiveState'] in ('active', 'activating', 'reloading'):
            return None
        return 0 if values['Result'] == 'success' else 1

    def terminate(self):
        run('systemctl', 'stop', self.unit)

    def kill(self):
        run('systemctl', 'kill', '--signal=SIGKILL', '--kill-whom=all', self.unit)

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while self.poll() is None:
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.unit, timeout)
            time.sleep(0.1)
        return self.poll()


def reboot_phase(directory, cleanup=False):
    directory = directory.resolve(strict=True)
    assert directory.stat().st_uid == 0 and directory.stat().st_mode & 0o077 == 0
    manifest_path = directory / 'reboot.json'
    assert manifest_path.stat().st_uid == 0 and manifest_path.stat().st_mode & 0o077 == 0
    manifest = json.loads(manifest_path.read_bytes())
    assert manifest_path.is_file() and not manifest_path.is_symlink()
    token = manifest['token']
    assert re.fullmatch(r'[0-9a-f]{16}', token)
    prefix = f'cat4igp-reboot-{token}'
    units = [f'{prefix}-{kind}.service' for kind in ('topology', 'controller', 'client0', 'client1')]
    assert manifest['units'] == units
    if cleanup:
        for unit in units:
            path = Path('/etc/systemd/system') / unit
            assert not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest() == manifest['unit_hashes'][unit], 'fixture unit changed; refusing cleanup'
        for unit in reversed(units):
            run('systemctl', 'disable', '--now', unit)
        for unit in units[2:]:
            run('systemctl', 'clean', '--what=state,runtime', unit)
        for unit in units:
            (Path('/etc/systemd/system') / unit).unlink()
        run('systemctl', 'daemon-reload')
        print(json.dumps({'result': 'CLEANED', 'persistent_secrets_retained_at': str(directory)}))
        return
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    assert boot != manifest['boot_id'], 'actual reboot required; boot ID unchanged'
    started = time.monotonic()
    unit_startup = {unit: dict(line.split('=', 1) for line in run('systemctl', 'show',
        '--property=ActiveState,MainPID,ActiveEnterTimestamp,ExecMainStartTimestamp', unit).splitlines()) for unit in units}
    def ready():
        return all(run('systemctl', 'show', '--value', '--property=ActiveState', unit).strip() == 'active' for unit in units)
    eventually(ready, 'fixture units did not start automatically after boot')
    assert hashlib.sha256(Path(manifest['client']).read_bytes()).hexdigest() == manifest['client_sha256']
    assert hashlib.sha256(Path(manifest['server']).read_bytes()).hexdigest() == manifest['server_sha256']
    evidence = []
    for index in range(2):
        state = directory / f'state{index}'
        current = json.loads((state / 'server.json').read_bytes())
        previous = manifest['enrollments'][index]
        for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key', 'controller_encryption_key',
                    'control_network_id', 'control_private_key', 'control_encryption_private_key', 'wg_private_key'):
            assert current.get(key) == previous.get(key), 'reboot changed enrollment identity'
        assert current['topology_revision'] >= previous['topology_revision']
        namespace = f'r{token[:8]}{index}'
        def command(*args):
            return run('ip', 'netns', 'exec', namespace, *args)
        def fresh():
            status = command(manifest['client'], '--config', directory / f'client{index}.toml', 'status')
            match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
            return match and int(match[1]) <= 90
        eventually(fresh, 'rebooted client lacks authenticated snapshot')
        names = command('wg', 'show', 'interfaces').split()
        assert set(names) == set(manifest['interfaces'][index])
        for slot, interface in enumerate(manifest['interfaces'][index]):
            assert command('wg', 'show', interface, 'public-key').strip() == manifest['public_keys'][slot][index]
            assert int(command('wg', 'show', interface, 'listen-port')) == manifest['ports'][index][slot]
            command('ip', 'addr', 'replace', f'198.18.{slot}.{index + 1}/30', 'dev', interface)
        evidence.append({'client': index, 'main_pid': int(run('systemctl', 'show', '--value', '--property=MainPID', units[index + 2]).strip())})
    for slot in range(2):
        for index in range(2):
            namespace = f'r{token[:8]}{index}'
            interface = manifest['interfaces'][index][slot]
            output = run('ip', 'netns', 'exec', namespace, 'env', 'LC_ALL=C', 'ping', '-n', '-c', '3', '-W', '2', '-I', interface, f'198.18.{slot}.{2-index}')
            summary = re.search(r'(\d+) packets transmitted, (\d+) received', output)
            assert summary and tuple(map(int, summary.groups())) == (3, 3)
            ping_replies(output, 3, 3)
            rows = run('ip', 'netns', 'exec', namespace, 'wg', 'show', interface, 'latest-handshakes').splitlines()
            assert len(rows) == 1
            peer, timestamp = rows[0].split()
            assert peer == manifest['public_keys'][slot][1-index]
            assert int(timestamp) >= manifest['prepared_unix_seconds'] and 0 <= time.time() - int(timestamp) <= 180
    print(json.dumps({'result': 'PASS', 'scope': 'actual reboot of scoped installed-unit fixture; not production boot availability',
        'previous_boot_id': manifest['boot_id'], 'current_boot_id': boot,
        'clients': evidence, 'tested_links': 2, 'bidirectional_ping': True,
        'unit_startup': unit_startup,
        'measured_verification_seconds': time.monotonic() - started}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--confirm-disposable', action='store_true', required=True)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--client', type=Path)
    reboot = parser.add_mutually_exclusive_group()
    reboot.add_argument('--prepare-reboot', type=Path)
    reboot.add_argument('--verify-reboot', type=Path)
    reboot.add_argument('--cleanup-reboot', type=Path)
    parser.add_argument('--nodes', type=int, choices=(2, 5), default=2,
                        help='enrolled daemon count; five nodes support only the baseline restore drill')
    parser.add_argument('--reference-traffic-seconds', type=int, default=0,
                        help='five-node synthetic concurrent TCP/UDP traffic duration (1..300 seconds; 0 disables)')
    parser.add_argument('--reference-controller-outage', action='store_true',
                        help='five-second controller outage during five-node reference traffic (requires at least 30 traffic seconds)')
    parser.add_argument('--reference-soak', action='store_true',
                        help='also run a 60-second reference-only traffic/controller-outage soak')
    parser.add_argument('--offline-client-restart', action='store_true',
                        help='reconstruct cached tunnels after client restart with controller offline; not revocation evidence')
    parser.add_argument('--damaged-cache-repair', action='store_true',
                        help='repair damaged topology cache online without changing revision journals')
    parser.add_argument('--offline-revocation', action='store_true',
                        help='after restore, isolate one control connection and verify reachable-peer revocation (requires nft)')
    parser.add_argument('--endpoint-roaming', action='store_true',
                        help='change client0 underlay addresses through authenticated ModifyConfig IPC')
    parser.add_argument('--client-crash-recovery', action='store_true',
                        help='SIGKILL/restart client0 with surviving kernel WireGuard devices and protected state')
    parser.add_argument('--client-upgrade-from', type=Path,
                        help='enroll with this compatible prior client, then restart both states with --client')
    reinstall = parser.add_mutually_exclusive_group()
    reinstall.add_argument('--client-reinstall-deb', type=Path,
                           help='same-version Debian package reinstall with enrolled states')
    reinstall.add_argument('--client-reinstall-arch', type=Path,
                           help='same-version Arch package reinstall with enrolled states')
    parser.add_argument('--packaged-service', action='store_true',
                        help='run enrolled clients with scoped copies of the installed systemd unit during package reinstall')
    parser.add_argument('--packaged-crash-recovery', action='store_true',
                        help='SIGKILL one scoped packaged unit and require automatic on-failure restart')
    args = parser.parse_args()
    if args.verify_reboot or args.cleanup_reboot:
        assert os.geteuid() == 0 and __debug__
        reboot_phase(args.verify_reboot or args.cleanup_reboot, bool(args.cleanup_reboot))
        return
    if not args.server or not args.client:
        parser.error('--server and --client are required for enrollment')
    if args.prepare_reboot and (not args.packaged_service or args.packaged_crash_recovery):
        parser.error('--prepare-reboot requires --packaged-service and excludes crash recovery')
    if args.packaged_crash_recovery and not args.packaged_service:
        parser.error('--packaged-crash-recovery requires --packaged-service')
    reinstall_package = args.client_reinstall_deb or args.client_reinstall_arch
    if reinstall_package and (args.client_upgrade_from or args.nodes != 2):
        parser.error('package reinstall requires two nodes and excludes --client-upgrade-from')
    if args.packaged_service and (not reinstall_package or any((args.reference_soak,
            args.offline_client_restart, args.damaged_cache_repair, args.offline_revocation,
            args.endpoint_roaming, args.client_crash_recovery))):
        parser.error('--packaged-service requires a package reinstall without other specialized modes')
    if args.packaged_service:
        assert Path('/proc/1/comm').read_text().strip() == 'systemd', '--packaged-service requires systemd as PID 1'
    if not 0 <= args.reference_traffic_seconds <= 300:
        parser.error('--reference-traffic-seconds must be 0 (disabled) or 1..300')
    if args.reference_traffic_seconds and args.nodes != 5:
        parser.error('--reference-traffic-seconds requires --nodes 5')
    if args.reference_controller_outage and (args.nodes != 5 or args.reference_traffic_seconds < 30):
        parser.error('--reference-controller-outage requires --nodes 5 and --reference-traffic-seconds 30..300')
    if args.nodes == 5 and any((args.reference_soak, args.offline_client_restart,
            args.client_crash_recovery, args.client_upgrade_from)):
        parser.error('--nodes 5 supports baseline restore, endpoint roaming, offline revocation and damaged-cache repair; other specialized modes require --nodes 2')
    assert __debug__, 'do not run with Python optimization: assertions are acceptance checks'
    assert os.geteuid() == 0, 'root in a disposable VM required'
    args.server = args.server.resolve(strict=True)
    args.client = args.client.resolve(strict=True)
    if reinstall_package:
        assert args.client == Path('/usr/bin/cat4igp-client'), 'reinstall requires the installed /usr/bin/cat4igp-client'
        reinstall_package = reinstall_package.resolve(strict=True)
        if args.client_reinstall_deb:
            args.client_reinstall_deb = reinstall_package
            assert run('dpkg-deb', '-f', reinstall_package, 'Package').strip() == 'cat4igp-client'
            version_command = ('dpkg-query', '-W', '-f=${Version}', 'cat4igp-client')
            installed_version = run(*version_command).strip()
            assert run('dpkg-query', '-W', '-f=${Status}', 'cat4igp-client').strip() == 'install ok installed'
            assert run('dpkg-deb', '-f', reinstall_package, 'Version').strip() == installed_version, 'reinstall must keep installed version'
            assert run('dpkg-deb', '-f', reinstall_package, 'Architecture').strip() == run('dpkg', '--print-architecture').strip()
            reinstall_command = ('dpkg', '--force-confold', '-i', reinstall_package)
            package_manager = 'dpkg'
        else:
            args.client_reinstall_arch = reinstall_package
            metadata = run('bsdtar', '-xOf', reinstall_package, '.PKGINFO')
            fields = {}
            for line in metadata.splitlines():
                if ' = ' in line:
                    key, value = line.split(' = ', 1)
                    fields.setdefault(key, []).append(value)
            assert fields.get('pkgname') == ['cat4igp-client']
            installed_info = run('pacman', '-Q', 'cat4igp-client').strip().split()
            assert len(installed_info) == 2 and installed_info[0] == 'cat4igp-client'
            installed_version = installed_info[1]
            assert fields.get('pkgver') == [installed_version], 'reinstall must keep installed version'
            assert fields.get('arch') == [os.uname().machine], 'package architecture must match VM'
            version_command = ('pacman', '-Q', 'cat4igp-client')
            reinstall_command = ('pacman', '-U', '--noconfirm', reinstall_package)
            package_manager = 'pacman'
    if args.client_upgrade_from:
        args.client_upgrade_from = args.client_upgrade_from.resolve(strict=True)
        assert hashlib.sha256(args.client_upgrade_from.read_bytes()).digest() != hashlib.sha256(args.client.read_bytes()).digest(), 'upgrade requires genuinely different client artifacts'
        probe = subprocess.run([str(args.client_upgrade_from), 'register-bundle', '--help'],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        assert probe.returncode == 0, 'baseline does not support register-bundle; incompatible historical enrollment CLI (no protocol shim)'
    if os.environ.get('CAT4IGP_RESTORE_NAMESPACE') != '1':
        env = dict(os.environ, CAT4IGP_RESTORE_NAMESPACE='1')
        os.execvpe('unshare', ['unshare', '--net', '--mount', '--', sys.executable,
                   str(Path(__file__).resolve()), '--confirm-disposable', '--server',
                   str(args.server), '--client', str(args.client), '--nodes', str(args.nodes),
                   '--reference-traffic-seconds', str(args.reference_traffic_seconds)] +
                   (['--reference-controller-outage'] if args.reference_controller_outage else []) +
                   (['--reference-soak'] if args.reference_soak else []) +
                   (['--offline-client-restart'] if args.offline_client_restart else []) +
                   (['--damaged-cache-repair'] if args.damaged_cache_repair else []) +
                   (['--offline-revocation'] if args.offline_revocation else []) +
                   (['--endpoint-roaming'] if args.endpoint_roaming else []) +
                   (['--client-crash-recovery'] if args.client_crash_recovery else []) +
                   (['--client-upgrade-from', str(args.client_upgrade_from)] if args.client_upgrade_from else []) +
                   (['--client-reinstall-deb', str(args.client_reinstall_deb)] if args.client_reinstall_deb else []) +
                   (['--client-reinstall-arch', str(args.client_reinstall_arch)] if args.client_reinstall_arch else []) +
                   (['--packaged-service'] if args.packaged_service else []) +
                   (['--packaged-crash-recovery'] if args.packaged_crash_recovery else []) +
                   (['--prepare-reboot', str(args.prepare_reboot.resolve())] if args.prepare_reboot else []), env)
    run('ip', 'link', 'set', 'lo', 'up')
    events = {}
    def mark(name):
        events[name] = time.time()
    with TemporaryDirectory(prefix='cat4igp-restore-') as directory, contextlib.ExitStack() as cleanup:
        os.umask(0o077)
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        certificates(tmp)
        backend = port()
        control = port()
        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                self.forward()
            def do_POST(self):
                self.forward()
            def forward(self):
                conn = http.client.HTTPConnection('127.0.0.1', backend, timeout=10)
                try:
                    body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    conn.request(self.command, self.path, body, dict(self.headers))
                    response = conn.getresponse()
                    data = response.read()
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {'connection', 'transfer-encoding', 'content-length'}:
                            self.send_header(key, value)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                finally:
                    conn.close()
        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(tmp / 'tls.pem', tmp / 'tls.key')
        proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        def close_proxy():
            proxy.shutdown()
            proxy.server_close()
            thread.join()
        cleanup.callback(close_proxy)
        origin = f'https://localhost:{proxy.server_port}'
        credentials = {'username': 'administrator', 'password': secrets.token_urlsafe(32)}
        secret_file(tmp / 'bootstrap.json', credentials)
        secret_file(tmp / 'jwt.json', {'origin': origin, 'issuer': 'drill', 'audience': 'drill',
                    'active': 'drill', 'keys': {'drill': secrets.token_hex(32)}})
        psk = '/key/swarm/psk/1.0.0/\n/base16/\n' + secrets.token_hex(32)
        db = tmp / 'controller.db'
        env = {k: os.environ[k] for k in ('PATH', 'HOME') if k in os.environ}
        env.update(DATABASE_URL=str(db), AUTO_MIGRATE='false',
                   BIND_HOST_PORT=f'127.0.0.1:{backend}',
                   CONTROL_BIND_MULTIADDR=f'/ip4/192.0.2.1/tcp/{control}',
                   CONTROL_PRIVATE_NETWORK_KEY=psk,
                   ADMIN_JWT_CONFIG_FILE=str(tmp / 'jwt.json'),
                   ADMIN_BOOTSTRAP_FILE=str(tmp / 'bootstrap.json'))
        log = cleanup.enter_context((tmp / 'controller.log').open('wb'))
        subprocess.run([args.server, 'migrate'], env=env, cwd=tmp, stdout=log, stderr=log, check=True)
        def start_server():
            process = subprocess.Popen([args.server], env=env, cwd=tmp, stdout=log, stderr=log)
            cleanup.callback(stop, process)
            def ready():
                assert process.poll() is None, 'controller exited; private logs withheld'
                with socket.create_connection(('127.0.0.1', backend), timeout=0.2):
                    return True
            eventually(ready, 'controller startup timeout')
            return process
        run('ip', 'link', 'add', 'drillbr', 'type', 'bridge')
        run('ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'drillbr')
        run('ip', 'link', 'set', 'drillbr', 'up')
        process = start_server()
        env.pop('ADMIN_BOOTSTRAP_FILE')
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cafile=str(tmp / 'ca.pem'))),
            urllib.request.HTTPCookieProcessor(jar))
        def api(path, body=None):
            request = urllib.request.Request(origin + '/admin/' + path,
                data=None if body is None else json.dumps(body).encode(),
                headers={'Origin': origin, 'Content-Type': 'application/json',
                         'Idempotency-Key': str(uuid.uuid4())})
            with client.open(request, timeout=10) as response:
                assert response.status == 200
                return json.load(response)
        api('login', credentials)
        mesh = api('actions', {'action': 'create_mesh', 'name': 'restore-drill',
                   'auto_wireguard': True, 'mtu': 1420})['mesh_id']
        eventually(lambda: re.search(r'controller peer id: (\S+)', (tmp / 'controller.log').read_text()), 'missing controller identity')
        peer = re.search(r'controller peer id: (\S+)', (tmp / 'controller.log').read_text())[1]
        with contextlib.closing(sqlite3.connect(db)) as conn:
            settings = dict(conn.execute('SELECT key,value FROM settings'))
        # Ed25519 protobuf private keys carry the 32-byte public key after the seed.
        private = bytes.fromhex(settings['control_private_key'])
        assert private[:4] == bytes.fromhex('08011240') and len(private) == 68
        signing = (bytes.fromhex('08011220') + private[-32:]).hex()
        clients = []
        active_client = args.client_upgrade_from or args.client
        def ns(index, *command):
            return run('ip', 'netns', 'exec', f'drill{index}', *command)
        service_units = {}
        def install_service(index, anchor):
            unit = f'cat4igp-drill-{tmp.name}-{index}.service'
            unit_path = Path('/run/systemd/system') / unit
            dropin = unit_path.with_name(unit + '.d')
            directory_name = unit.removesuffix('.service')
            assert not unit_path.exists() and not dropin.exists()
            def remove_service():
                run('systemctl', 'stop', unit)
                run('systemctl', 'clean', '--what=state,runtime', unit)
                shutil.rmtree(dropin)
                unit_path.unlink()
                run('systemctl', 'daemon-reload')
            unit_path.write_bytes(Path('/usr/lib/systemd/system/cat4igp-client.service').read_bytes())
            dropin.mkdir()
            cleanup.callback(remove_service)
            def quote(value):
                return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'
            config = tmp / f'client{index}.toml'
            (dropin / 'drill.conf').write_text('[Service]\nExecStartPre=\n'
                f'ExecStartPre=/usr/bin/test -r {quote(config)}\nExecStart=\n'
                f'ExecStart=/usr/bin/cat4igp-client daemon --config {quote(config)}\n'
                f'NetworkNamespacePath=/proc/{anchor.pid}/ns/net\n'
                f'StateDirectory={directory_name}\nRuntimeDirectory={directory_name}\n'
                f'WorkingDirectory={quote(tmp)}\n'
                f'StandardOutput=append:{tmp}/client{index}.log\nStandardError=append:{tmp}/client{index}.log\n')
            service_units[index] = (unit, unit_path)
            run('systemctl', 'daemon-reload')
        def start_client(index):
            if args.packaged_service:
                if index not in service_units:
                    anchor = subprocess.Popen(['ip', 'netns', 'exec', f'drill{index}', 'sleep', 'infinity'])
                    cleanup.callback(stop, anchor)
                    namespace = ns(index, 'readlink', '/proc/self/ns/net').strip()
                    eventually(lambda: anchor.poll() is None and
                               os.readlink(f'/proc/{anchor.pid}/ns/net') == namespace,
                               'systemd namespace anchor did not enter client namespace')
                    install_service(index, anchor)
                run('systemctl', 'start', service_units[index][0])
                proc = ServiceProcess(service_units[index][0])
            else:
                proc = subprocess.Popen(['ip', 'netns', 'exec', f'drill{index}', str(active_client),
                        '--config', str(tmp / f'client{index}.toml'), 'daemon'], cwd=tmp,
                        env=env, stdout=clients[index]['log'], stderr=clients[index]['log'])
            cleanup.callback(stop, proc)
            clients[index]['process'] = proc
            return proc
        enrollment_started = int(time.time())
        for index in range(args.nodes):
            name = f'drill{index}'
            run('ip', 'netns', 'add', name)
            cleanup.callback(subprocess.run, ['ip', 'netns', 'del', name], check=False)
            # Permit root-group ICMP datagram probes only in this owned namespace.
            ns(index, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 0')
            # Stop daemons before deleting their namespaces during unwinding.
            run('ip', 'link', 'add', f'veth{index}', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', name)
            run('ip', 'link', 'set', f'veth{index}', 'master', 'drillbr')
            run('ip', 'link', 'set', f'veth{index}', 'up')
            ns(index, 'ip', 'addr', 'add', f'192.0.2.{index + 2}/24', 'dev', 'eth0')
            ns(index, 'ip', '-6', 'addr', 'add', f'fd42:31::{index + 2}/64', 'dev', 'eth0', 'nodad')
            ns(index, 'ip', 'link', 'set', 'eth0', 'up')
            ns(index, 'ip', 'link', 'set', 'lo', 'up')
            state = tmp / f'state{index}'
            state.mkdir(mode=0o700)
            config = tmp / f'client{index}.toml'
            config.write_text(f'daemon_socket = "{tmp}/client{index}.sock"\ndata_dir = "{state}"\n'
                f'public_hostname_ipv4 = "192.0.2.{index + 2}"\n'
                f'public_hostname_ipv6 = "fd42:31::{index + 2}"\n'
                '[port_range]\nmin = 51820\nmax = 51920\n[tunnel_protocols]\nwireguard = true\nl2tp = false\n')
            clients.append({'log': cleanup.enter_context((tmp / f'client{index}.log').open('wb')), 'state': state})
            start_client(index)
            eventually(lambda: (tmp / f'client{index}.sock').exists(), 'daemon socket timeout')
            invite = api('invites', {'max_uses': 1, 'expires_at': None, 'join_mesh': mesh})
            bundle = tmp / f'bundle{index}.json'
            secret_file(bundle, {'version': 1, 'bootstrap_addresses': [f'/ip4/192.0.2.1/tcp/{control}/p2p/{peer}'],
                'controller_peer_id': peer, 'controller_signing_key': signing,
                'network_id': settings['control_network_id'], 'private_network_key': psk,
                'invitation_code': invite['invite_code']})
            ns(index, active_client, '--config', config, 'register-bundle', '--bundle', bundle)
            bundle.unlink()
            mark('last_acknowledged_snapshot_change')
        def inventory():
            return api('inventory')
        expected_tunnels = args.nodes * (args.nodes - 1)
        def full_mesh():
            value = inventory()
            return value if len(value['tunnels']) == expected_tunnels else None
        topology = eventually(full_mesh, 'dual-stack full-mesh tunnels not created')
        node_ids = [json.loads((item['state'] / 'server.json').read_bytes())['control_node_id']
                    for item in clients]
        assert len(set(node_ids)) == args.nodes
        assert {node['id'] for node in topology['nodes']} == set(node_ids)
        node_indices = {node: index for index, node in enumerate(node_ids)}
        links = sorted(topology['tunnels'], key=lambda tunnel: tunnel['id'])
        assert len({link['id'] for link in links}) == expected_tunnels
        assert {(min(link['node_id_peer1'], link['node_id_peer2']),
                 max(link['node_id_peer1'], link['node_id_peer2']), link['ipv6']) for link in links} == {
                     (a, b, ipv6) for a, b in combinations(sorted(node_ids), 2) for ipv6 in (False, True)}
        tunnel_ids = [[link['id'] for link in links if node in
                       (link['node_id_peer1'], link['node_id_peer2'])] for node in node_ids]
        def devices():
            result = []
            for index, expected in enumerate(tunnel_ids):
                names = ns(index, 'wg', 'show', 'interfaces').split()
                if len(names) != 2 * (args.nodes - 1):
                    return None
                cache = json.loads((clients[index]['state'] / 'topology-cache.json').read_bytes())
                if cache['identity']['node_id'] != node_ids[index]:
                    return None
                cached = {tunnel['tunnel_id']: tunnel for tunnel in cache['snapshot']['tunnels']}
                if set(cached) != set(expected) or set(map(int, cache['ports'])) != set(expected):
                    return None
                # Authenticated persisted tunnel-ID -> port bindings identify actual
                # kernel names; sorted interface names do not identify mesh peers.
                by_port = {int(ns(index, 'wg', 'show', name, 'listen-port')): name for name in names}
                if len(by_port) != len(names):
                    return None
                row = []
                for tunnel_id in expected:
                    name = by_port.get(cache['ports'][str(tunnel_id)])
                    if name is None:
                        return None
                    link = next(link for link in links if link['id'] == tunnel_id)
                    remote = link['node_id_peer2'] if link['node_id_peer1'] == node_ids[index] else link['node_id_peer1']
                    if cached[tunnel_id]['peer_node_id'] != remote or cached[tunnel_id]['endpoint_ipv6'] != link['ipv6']:
                        return None
                    if ns(index, 'wg', 'show', name, 'peers').split() != [cached[tunnel_id]['public_key']]:
                        return None
                    endpoints = ns(index, 'wg', 'show', name, 'endpoints').splitlines()
                    if len(endpoints) != 1 or endpoints[0].split() != [cached[tunnel_id]['public_key'], cached[tunnel_id]['remote_endpoint']]:
                        return None
                    row.append(name)
                result.append(row)
            return result
        interfaces = eventually(devices, 'WireGuard reconciliation timeout')
        def traffic_pair(link, slot, fresh_after=0):
            indices = sorted(node_indices[link[key]] for key in ('node_id_peer1', 'node_id_peer2'))
            names = [interfaces[index][tunnel_ids[index].index(link['id'])] for index in indices]
            for side, (index, interface) in enumerate(zip(indices, names)):
                ns(index, 'ip', 'addr', 'replace', f'198.18.{slot}.{side + 1}/30', 'dev', interface)
                ns(index, 'ip', 'link', 'set', interface, 'up')
            probes = []
            for side, (index, interface) in enumerate(zip(indices, names)):
                text = ns(index, 'env', 'LC_ALL=C', 'ping', '-n', '-c', '3', '-W', '2',
                          '-I', interface, f'198.18.{slot}.{2 - side}')
                summary = re.search(r'(\d+) packets transmitted, (\d+) received', text)
                assert summary, 'baseline/restore ping summary missing'
                sent, received = map(int, summary.groups())
                if sent != 3 or received != sent:
                    return None
                ping_replies(text, sent, received)
                probes.append({'source_client': index, 'transmitted': sent, 'received': received})
            handshakes = []
            identities = []
            peers = []
            for index, interface in zip(indices, names):
                identities.append(ns(index, 'wg', 'show', interface, 'public-key').strip())
                rows = ns(index, 'wg', 'show', interface, 'latest-handshakes').splitlines()
                assert len(rows) == 1
                remote_key, timestamp = rows[0].split()
                peers.append(remote_key)
                timestamp = int(timestamp)
                if timestamp < fresh_after or time.time() - timestamp > 180:
                    return None
                handshakes.append(timestamp)
            assert peers == list(reversed(identities)), 'tunnel peer identities do not match endpoints'
            return {'tunnel_id': link['id'], 'underlay_ipv6': link['ipv6'],
                    'client_indices': indices, 'interfaces': names, 'probes': probes,
                    'public_keys': identities, 'handshakes': handshakes, 'bidirectional_ping': True}
        def traffic(fresh_after=0):
            paths = [traffic_pair(link, slot, fresh_after) for slot, link in enumerate(links)]
            if not all(paths):
                return None
            return {'public_keys': [path['public_keys'] for path in paths],
                    'handshakes': [path['handshakes'] for path in paths],
                    'bidirectional_ping': True, 'tested_links': len(paths), 'links': paths}
        def authenticated_ages():
            ages = []
            for index, item in enumerate(clients):
                assert item['process'].poll() is None, 'enrolled daemon exited'
                status = ns(index, args.client, '--config', tmp / f'client{index}.toml', 'status')
                match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                if not match or int(match[1]) > 90:
                    return None
                ages.append(int(match[1]))
            return ages
        def resources():
            def memory(proc):
                assert proc.poll() is None, 'measured daemon exited'
                status = Path(f'/proc/{proc.pid}/status').read_text()
                return {label: int(re.search(rf'^{field}:\s+(\d+) kB$', status, re.MULTILINE)[1])
                        for label, field in (('rss_kib', 'VmRSS'), ('peak_rss_kib', 'VmHWM'))}
            return {'controller': memory(process),
                    'clients': [memory(item['process']) for item in clients],
                    'wireguard_interfaces_per_client': [len(row) for row in interfaces]}
        baseline_path = eventually(lambda: traffic(enrollment_started), 'baseline handshake/traffic timeout')
        baseline_ages = eventually(authenticated_ages, 'baseline clients lack authenticated fresh snapshots')
        baseline_resources = resources()
        baseline = inventory()
        mark('baseline_verified')
        mixed_traffic_report = None
        if args.reference_traffic_seconds:
            streams = []
            started = time.monotonic()
            # Four actual mesh edges span all five daemons and both underlay families.
            for edge in range(args.nodes - 1):
                path = next(path for path in baseline_path['links']
                            if path['client_indices'] == [edge, edge + 1]
                            and path['underlay_ipv6'] == bool(edge % 2))
                slot = next(slot for slot, link in enumerate(links) if link['id'] == path['tunnel_id'])
                source, destination = path['client_indices']
                source_ip, destination_ip = f'198.18.{slot}.1', f'198.18.{slot}.2'
                for protocol in ('tcp', 'udp'):
                    command = [sys.executable, '-c', REFERENCE_TRAFFIC]
                    receiver = subprocess.Popen(['ip', 'netns', 'exec', f'drill{destination}',
                        *command, 'server', protocol, destination_ip, source_ip, '42000',
                        str(args.reference_traffic_seconds)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True)
                    cleanup.callback(stop, receiver)
                    assert receiver.stdout.readline().strip() == 'READY', 'traffic receiver did not start'
                    streams.append({'protocol': protocol, 'path': path, 'receiver': receiver,
                        'command': ['ip', 'netns', 'exec', f'drill{source}', *command, 'client',
                            protocol, source_ip, destination_ip, '42000', str(args.reference_traffic_seconds)]})
            for stream in streams:
                stream['sender'] = subprocess.Popen(stream['command'], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True)
                cleanup.callback(stop, stream['sender'])
            traffic_started = time.monotonic()
            mark('reference_traffic_started')
            outage_report = None
            if args.reference_controller_outage:
                time.sleep(2)
                assert all(stream['sender'].poll() is None and stream['receiver'].poll() is None
                           for stream in streams), 'streams ended before controller outage'
                mark('reference_controller_stop_requested')
                stop(process)
                assert process.poll() is not None
                outage_started = time.monotonic()
                mark('reference_controller_stopped')
                time.sleep(5)
                assert all(item['process'].poll() is None for item in clients), 'client exited during controller outage'
                assert all(stream['sender'].poll() is None and stream['receiver'].poll() is None
                           for stream in streams), 'streams ended during controller outage'
                mark('reference_controller_restart_requested')
                restart_started = time.monotonic()
                process = start_server()
                mark('reference_controller_ready')
                api('login', credentials)
                def fresh_after_outage():
                    assert all(stream['sender'].poll() is None and stream['receiver'].poll() is None
                               for stream in streams), 'streams ended before controller reconnection'
                    ages = authenticated_ages()
                    if not ages or any(age > 5 or age >= time.monotonic() - restart_started for age in ages):
                        return None
                    return ages
                remaining = args.reference_traffic_seconds - (time.monotonic() - traffic_started) - 2
                assert remaining > 0, 'controller startup consumed reference traffic window'
                outage_ages = eventually(fresh_after_outage, 'clients did not authenticate after outage during traffic',
                                         timeout=remaining)
                mark('reference_controller_reconnected_during_traffic')
                assert inventory()['tunnels'] == baseline['tunnels'], 'controller restart changed tunnel inventory'
                outage_report = {'scope': 'same-database controller restart during synthetic traffic; separate from restore',
                    'requested_stopped_seconds': 5,
                    'stopped_until_restart_requested_seconds': restart_started - outage_started,
                    'stopped_until_reconnected_seconds': time.monotonic() - outage_started,
                    'restart_reconciliation_seconds': time.monotonic() - restart_started,
                    'authenticated_snapshot_age_seconds': outage_ages,
                    'all_stream_processes_active_at_stop_and_reconnection': True}
            else:
                time.sleep(args.reference_traffic_seconds / 2)
            assert all(stream['sender'].poll() is None and stream['receiver'].poll() is None
                       for stream in streams), 'reference streams did not overlap'
            concurrent_resources = resources()
            measurements = []
            for stream in streams:
                output, error = stream['sender'].communicate(timeout=args.reference_traffic_seconds + 20)
                assert stream['sender'].returncode == 0, f"{stream['protocol']} sender failed: {error}"
                sent = json.loads(output)
                output, error = stream['receiver'].communicate(timeout=args.reference_traffic_seconds + 20)
                assert stream['receiver'].returncode == 0, f"{stream['protocol']} receiver failed: {error}"
                received = json.loads(output)
                assert 0 < sent['bytes'] <= received['bytes'] <= sent['sent_bytes']
                if sent['bytes'] == received['bytes']:
                    assert sent['sha256'] == received['sha256']
                if stream['protocol'] == 'tcp':
                    assert sent['bytes'] == received['bytes'] == sent['sent_bytes']
                    assert sent['sha256'] == received['sha256']
                measurements.append({'protocol': stream['protocol'],
                    'tunnel_id': stream['path']['tunnel_id'],
                    'underlay_ipv6': stream['path']['underlay_ipv6'],
                    'client_indices': stream['path']['client_indices'],
                    'sender': sent, 'receiver': received})
            assert all(item['process'].poll() is None for item in clients), 'daemon exited during mixed traffic'
            mark('reference_traffic_verified')
            mixed_traffic_report = {'scope': 'synthetic concurrent TCP/UDP echo on four mesh paths; not production mixed traffic or 80-node capacity',
                'requested_seconds_per_stream': args.reference_traffic_seconds,
                'measured_wall_seconds': time.monotonic() - started,
                'streams': measurements, 'resources_during_traffic': concurrent_resources,
                'resources_after_traffic': resources(),
                'controller_outage': outage_report,
                'controller_snapshot_age_seconds': eventually(authenticated_ages, 'clients lost controller freshness during traffic')}
        upgrade_report = None
        reinstall_report = None
        packaged_crash_report = None
        if args.packaged_crash_recovery:
            def observed_kernel():
                return [[{'interface': name,
                    'ifindex': json.loads(ns(index, 'ip', '-j', 'link', 'show', name))[0]['ifindex'],
                    'public_key': ns(index, 'wg', 'show', name, 'public-key').strip(),
                    'listen_port': int(ns(index, 'wg', 'show', name, 'listen-port'))}
                    for name in row] for index, row in enumerate(interfaces)]
            before_kernel = observed_kernel()
            before_enrollments = [json.loads((item['state'] / 'server.json').read_bytes()) for item in clients]
            crashed = clients[0]['process']
            old_pid = crashed.pid
            old_restarts = int(run('systemctl', 'show', '--value', '--property=NRestarts', crashed.unit).strip())
            crash_started = time.monotonic()
            mark('packaged_client_sigkill')
            run('systemctl', 'kill', '--signal=SIGKILL', '--kill-whom=main', crashed.unit)
            def automatically_restarted():
                state = run('systemctl', 'show', '--value', '--property=ActiveState', crashed.unit).strip()
                pid = crashed.pid
                restarts = int(run('systemctl', 'show', '--value', '--property=NRestarts', crashed.unit).strip())
                return pid if state == 'active' and pid > 0 and pid != old_pid and restarts > old_restarts else None
            new_pid = eventually(automatically_restarted, 'packaged unit did not automatically restart')
            def crash_freshness():
                ages = authenticated_ages()
                if not ages or ages[0] > 5 or ages[0] >= time.monotonic() - crash_started:
                    return None
                return ages
            recovered_ages = eventually(crash_freshness, 'automatically restarted client lacks fresh authenticated snapshot')
            interfaces = eventually(devices, 'automatic packaged restart failed reconciliation')
            recovered_path = eventually(traffic, 'automatic packaged restart failed traffic')
            assert recovered_path['public_keys'] == baseline_path['public_keys']
            after_kernel = observed_kernel()
            for before_row, after_row in zip(before_kernel, after_kernel):
                assert [(row['interface'], row['public_key'], row['listen_port']) for row in before_row] == [
                    (row['interface'], row['public_key'], row['listen_port']) for row in after_row], 'automatic restart changed tunnel identities or ports'
            for item, previous in zip(clients, before_enrollments):
                current = json.loads((item['state'] / 'server.json').read_bytes())
                for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                            'controller_encryption_key', 'control_network_id', 'control_private_key',
                            'control_encryption_private_key', 'wg_private_key'):
                    assert current.get(key) == previous.get(key), 'automatic restart changed enrollment identity'
                assert current['topology_revision'] >= previous['topology_revision']
            mark('packaged_client_automatic_restart_verified')
            packaged_crash_report = {'scope': 'SIGKILL main process; installed-unit Restart=on-failure with drill overrides; no manual tunnel deletion',
                'old_main_pid': old_pid, 'new_main_pid': new_pid,
                'automatic_restart_count_increment': int(run('systemctl', 'show', '--value', '--property=NRestarts', crashed.unit).strip()) - old_restarts,
                'kernel_before': before_kernel, 'kernel_after': after_kernel,
                'kernel_ifindices_preserved': before_kernel == after_kernel,
                'authenticated_snapshot_age_seconds': recovered_ages,
                'identities_ports_and_bidirectional_traffic_preserved': True,
                'measured_verification_seconds': time.monotonic() - crash_started}
            baseline_path = recovered_path
            baseline = inventory()
        if reinstall_package:
            before_hash = hashlib.sha256(args.client.read_bytes()).hexdigest()
            states = []
            original_ports = [[int(ns(index, 'wg', 'show', name, 'listen-port')) for name in row]
                              for index, row in enumerate(interfaces)]
            for item in clients:
                stop(item['process'])
                assert item['process'].poll() is not None
                states.append({name: (item['state'] / name).read_bytes() for name in
                               ('server.json', 'topology-cache.json', 'topology-revision.json')})
            mark('client_package_reinstall_started')
            reinstall_started = time.monotonic()
            run(*reinstall_command)
            installed_after = run(*version_command).strip()
            assert installed_after == (installed_version if package_manager == 'dpkg' else f'cat4igp-client {installed_version}')
            if package_manager == 'dpkg':
                assert run('dpkg-query', '-W', '-f=${Status}', 'cat4igp-client').strip() == 'install ok installed'
            assert hashlib.sha256(args.client.read_bytes()).hexdigest() == before_hash, 'same-version reinstall changed client artifact'
            if args.packaged_service:
                for unit, unit_path in service_units.values():
                    unit_path.write_bytes(Path('/usr/lib/systemd/system/cat4igp-client.service').read_bytes())
                run('systemctl', 'daemon-reload')
            for item, saved in zip(clients, states):
                for name, content in saved.items():
                    assert (item['state'] / name).read_bytes() == content, 'package transaction changed enrolled state'
            for index in range(2):
                start_client(index)
            reinstall_ages = eventually(authenticated_ages, 'reinstalled clients failed authenticated reconnection')
            interfaces = eventually(devices, 'reinstalled devices failed reconciliation')
            reinstalled_path = eventually(traffic, 'reinstalled clients failed bidirectional traffic')
            assert reinstalled_path['public_keys'] == baseline_path['public_keys']
            assert [[int(ns(index, 'wg', 'show', name, 'listen-port')) for name in row]
                    for index, row in enumerate(interfaces)] == original_ports
            for item, saved in zip(clients, states):
                previous = json.loads(saved['server.json'])
                current = json.loads((item['state'] / 'server.json').read_bytes())
                for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                            'controller_encryption_key', 'control_network_id', 'control_private_key',
                            'control_encryption_private_key', 'wg_private_key'):
                    assert current.get(key) == previous.get(key), 'reinstall changed enrollment identity'
                assert current['topology_revision'] >= previous['topology_revision']
            mark('client_package_reinstall_verified')
            reinstall_report = {'scope': 'actual same-version same-artifact package reinstall; NOT a version upgrade or downgrade',
                'package_manager': package_manager,
                'package_version': installed_version, 'client_sha256': before_hash,
                'package_sha256': hashlib.sha256(reinstall_package.read_bytes()).hexdigest(),
                'enrolled_state_unchanged_by_transaction': True,
                'identities_ports_and_bidirectional_traffic_preserved': True,
                'authenticated_snapshot_age_seconds': reinstall_ages,
                'service_lifecycle': 'scoped installed-unit copies with config/network/state-directory overrides' if args.packaged_service else 'direct subprocesses; no systemd lifecycle claim',
                'measured_verification_seconds': time.monotonic() - reinstall_started}
            baseline_path = reinstalled_path
            baseline = inventory()
        if args.prepare_reboot:
            destination = args.prepare_reboot.resolve()
            assert not destination.exists(), 'reboot fixture directory must be new'
            assert str(destination).startswith('/opt/'), 'persistent reboot fixture must be under /opt'
            assert re.fullmatch(r'/opt/[A-Za-z0-9_./-]+', str(destination)) and '%' not in str(destination)
            assert re.fullmatch(r'/[A-Za-z0-9_./-]+', str(args.server)), 'server path must be unit-safe'
            destination.mkdir(mode=0o700, parents=True)
            persistent_server = destination / 'cat4igp-server'
            shutil.copy2(args.server, persistent_server)
            token = secrets.token_hex(8)
            prefix = f'cat4igp-reboot-{token}'
            units = [f'{prefix}-{kind}.service' for kind in ('topology', 'controller', 'client0', 'client1')]
            for item in clients:
                stop(item['process'])
            stop(process)
            for index, item in enumerate(clients):
                shutil.copytree(item['state'], destination / f'state{index}')
                config = (tmp / f'client{index}.toml').read_text().replace(str(tmp), str(destination))
                (destination / f'client{index}.toml').write_text(config)
            with contextlib.closing(sqlite3.connect(db)) as source, contextlib.closing(sqlite3.connect(destination / 'controller.db')) as target:
                source.backup(target)
            for name in ('jwt.json', 'tls.pem', 'tls.key', 'ca.pem'):
                shutil.copy2(tmp / name, destination / name)
            persistent_env = {key: value.replace(str(tmp), str(destination)) for key, value in env.items()}
            secret_file(destination / 'controller-env.json', persistent_env)
            (destination / 'start-controller.py').write_text(
                'import json, os\nfrom pathlib import Path\n'
                'directory = Path(__file__).resolve().parent\n'
                'environment = json.loads((directory / "controller-env.json").read_bytes())\n'
                'binary = str(directory / "cat4igp-server")\n'
                'os.execve(binary, [binary], environment)\n')
            bridge = f'b{token[:8]}'
            topology_commands = [f'ip link add {bridge} type bridge',
                f'ip addr add 192.0.2.1/24 dev {bridge}', f'ip link set {bridge} up']
            for index in range(2):
                namespace, veth = f'r{token[:8]}{index}', f'v{token[:8]}{index}'
                topology_commands += [f'ip netns add {namespace}',
                    f'ip link add {veth} type veth peer name eth0 netns {namespace}',
                    f'ip link set {veth} master {bridge}', f'ip link set {veth} up',
                    f'ip -n {namespace} addr add 192.0.2.{index+2}/24 dev eth0',
                    f'ip -n {namespace} -6 addr add fd42:31::{index+2}/64 dev eth0 nodad',
                    f'ip -n {namespace} link set eth0 up', f'ip -n {namespace} link set lo up']
            (destination / 'topology.sh').write_text('#!/bin/sh\nset -eu\n' + '\n'.join(topology_commands) + '\n')
            stop_commands = [f'ip netns del r{token[:8]}{index}' for index in range(2)]
            stop_commands += [f'ip link del {bridge}']
            (destination / 'stop-topology.sh').write_text('#!/bin/sh\nset -eu\n' + '\n'.join(stop_commands) + '\n')
            definitions = {
                units[0]: f'[Unit]\nDescription=Owned reboot fixture topology\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh {destination}/topology.sh\nExecStop=/bin/sh {destination}/stop-topology.sh\n[Install]\nWantedBy=multi-user.target\n',
                units[1]: f'[Unit]\nDescription=Owned reboot fixture controller\nRequires={units[0]}\nAfter={units[0]}\n[Service]\nExecStart=/usr/bin/python3 {destination}/start-controller.py\nWorkingDirectory={destination}\nRestart=on-failure\nUMask=0077\n[Install]\nWantedBy=multi-user.target\n'}
            installed_unit = Path('/usr/lib/systemd/system/cat4igp-client.service').read_text()
            for index in range(2):
                definitions[units[index+2]] = installed_unit + (
                    f'\n[Unit]\nRequires={units[0]}\nAfter={units[0]} {units[1]}\n'
                    f'[Service]\nExecStartPre=\nExecStartPre=/usr/bin/test -r {destination}/client{index}.toml\n'
                    f'ExecStart=\nExecStart=/usr/bin/cat4igp-client daemon --config {destination}/client{index}.toml\n'
                    f'NetworkNamespacePath=/run/netns/r{token[:8]}{index}\n'
                    f'StateDirectory={prefix}-client{index}\nRuntimeDirectory={prefix}-client{index}\n')
            manifest = {'token': token, 'units': units,
                'unit_hashes': {unit: hashlib.sha256(content.encode()).hexdigest() for unit, content in definitions.items()},
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                'prepared_unix_seconds': int(time.time()), 'client': str(args.client), 'server': str(persistent_server),
                'client_sha256': hashlib.sha256(args.client.read_bytes()).hexdigest(),
                'server_sha256': hashlib.sha256(args.server.read_bytes()).hexdigest(),
                'interfaces': interfaces, 'public_keys': baseline_path['public_keys'],
                'ports': original_ports,
                'enrollments': [json.loads((item['state'] / 'server.json').read_bytes()) for item in clients]}
            secret_file(destination / 'reboot.json', manifest)
            for unit, content in definitions.items():
                path = Path('/etc/systemd/system') / unit
                assert not path.exists(), 'owned unit collision'
                path.write_text(content)
            run('systemctl', 'daemon-reload')
            run('systemctl', 'enable', *units)
            print(json.dumps({'result': 'PREPARED', 'reboot_required': True, 'fixture': str(destination),
                'scope': 'persistent scoped packaged units; no reboot success claimed until verify'}))
            return
        if args.client_upgrade_from:
            prior_hash = hashlib.sha256(active_client.read_bytes()).hexdigest()
            current_hash = hashlib.sha256(args.client.read_bytes()).hexdigest()
            original_ports = [[int(ns(i, 'wg', 'show', interface, 'listen-port'))
                               for interface in row] for i, row in enumerate(interfaces)]
            previous = []
            for index, item in enumerate(clients):
                stop(item['process'])
                previous.append(json.loads((item['state'] / 'server.json').read_bytes()))
                shutil.copytree(item['state'], tmp / f'pre-upgrade-state{index}')
            mark('client_upgrade_started')
            started = time.monotonic()
            active_client = args.client
            for index in range(2):
                start_client(index)
            ages = []
            def upgraded_clients_authenticated():
                current_ages = []
                for index in range(2):
                    assert clients[index]['process'].poll() is None, 'upgraded daemon exited'
                    status = ns(index, active_client, '--config', tmp / f'client{index}.toml', 'status')
                    match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                    if not match or int(match[1]) > 90:
                        return False
                    current_ages.append(int(match[1]))
                ages[:] = current_ages
                return True
            eventually(upgraded_clients_authenticated, 'upgraded clients did not accept authenticated snapshots')
            interfaces = eventually(devices, 'upgraded devices did not reconcile')
            upgraded_path = eventually(traffic, 'upgraded clients failed bidirectional traffic')
            assert upgraded_path['public_keys'] == baseline_path['public_keys']
            assert [[int(ns(i, 'wg', 'show', interface, 'listen-port'))
                     for interface in row] for i, row in enumerate(interfaces)] == original_ports
            for item, old in zip(clients, previous):
                current = json.loads((item['state'] / 'server.json').read_bytes())
                for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                            'controller_encryption_key', 'control_network_id', 'control_private_key',
                            'control_encryption_private_key', 'wg_private_key'):
                    assert current.get(key) == old.get(key), 'upgrade changed enrollment identity'
                assert current['topology_revision'] >= old['topology_revision']
            mark('client_upgrade_verified')
            upgrade_report = {'scope': 'operator-supplied compatible prior binary; not package-manager upgrade or downgrade',
                'prior_binary_sha256': prior_hash, 'current_binary_sha256': current_hash,
                'same_enrolled_states': True, 'authenticated_snapshot_ages_seconds': ages,
                'identities_ports_and_bidirectional_traffic_preserved': True,
                'verification_interval_seconds': time.monotonic() - started}
            baseline_path = upgraded_path
            baseline = inventory()
        crash_report = None
        if args.client_crash_recovery:
            def kernel_state():
                return [[{'name': interface,
                    'ifindex': json.loads(ns(i, 'ip', '-j', 'link', 'show', interface))[0]['ifindex'],
                    'public_key': ns(i, 'wg', 'show', interface, 'public-key').strip(),
                    'listen_port': int(ns(i, 'wg', 'show', interface, 'listen-port'))}
                    for interface in row] for i, row in enumerate(interfaces)]
            original_kernel = kernel_state()
            original_identity = json.loads((clients[0]['state'] / 'server.json').read_bytes())
            crashed = clients[0]['process']
            probes = []
            for slot in range(2):
                for index in range(2):
                    output = cleanup.enter_context((tmp / f'crash-{slot}-{index}.log').open('w+b'))
                    probe = subprocess.Popen(['ip', 'netns', 'exec', f'drill{index}',
                        'ping', '-n', '-O', '-i', '0.2', '-W', '1', '-I',
                        interfaces[index][slot], f'198.18.{slot}.{2 - index}'],
                        stdout=output, stderr=output, env=dict(os.environ, LC_ALL='C'))
                    cleanup.callback(stop, probe)
                    probes.append((slot, index, probe, output))
            time.sleep(1)
            started = time.monotonic()
            mark('client_sigkill')
            crashed.kill()
            assert crashed.wait(timeout=10) == -9
            assert kernel_state() == original_kernel, 'daemon crash changed surviving kernel devices'
            # No cache reset, re-enrollment, interface deletion or manual socket cleanup.
            assert json.loads((clients[0]['state'] / 'server.json').read_bytes()) == original_identity
            start_client(0)
            def authenticated_restart():
                assert clients[0]['process'].poll() is None, 'crashed client failed restart'
                status = ns(0, args.client, '--config', tmp / 'client0.toml', 'status')
                match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                return match and int(match[1]) <= 90
            eventually(authenticated_restart, 'crashed client did not authenticate a new controller snapshot')
            recovered_path = eventually(traffic, 'traffic failed after native client crash recovery')
            assert kernel_state() == original_kernel, 'restart replaced device identity or port'
            recovered_identity = json.loads((clients[0]['state'] / 'server.json').read_bytes())
            for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                        'controller_encryption_key', 'control_network_id', 'control_private_key',
                        'control_encryption_private_key', 'wg_private_key'):
                assert recovered_identity.get(key) == original_identity.get(key), 'crash recovery changed enrollment identity'
            assert recovered_identity['topology_revision'] >= original_identity['topology_revision']
            mark('client_crash_service_verified')
            time.sleep(1)
            measurements = []
            for slot, index, probe, output in probes:
                probe.send_signal(2)
                assert probe.wait(timeout=5) in (0, 1)
                output.seek(0)
                text = output.read().decode()
                summary = re.search(r'(\d+) packets transmitted, (\d+) received', text)
                assert summary, 'crash probe summary missing'
                sent, received = map(int, summary.groups())
                assert sent > 0 and received > 0
                replies = ping_replies(text, sent, received)
                longest = current = 0
                for sequence in range(1, sent + 1):
                    current = 0 if sequence in replies else current + 1
                    longest = max(longest, current)
                measurements.append({'link_slot': slot, 'source_client': index,
                    'sent': sent, 'received': received,
                    'loss_percent': 100 * (sent - received) / sent,
                    'max_missing_probe_interval_seconds': longest * 0.2})
            crash_report = {'scope': 'native kernel WireGuard only; no PPP or service-manager cleanup',
                'sigkill_same_state_restart': True, 'authenticated_snapshot_after_restart': True,
                'kernel_ifindices_identities_ports_preserved': True, 'bidirectional_traffic': True,
                'measured_verification_interval_seconds': time.monotonic() - started,
                'traffic_outage_measurement': measurements,
                'measurement_resolution_seconds': 0.2, 'production_objective_met': 'NOT CLAIMED'}
            baseline_path = recovered_path
            baseline = inventory()
        roaming_report = None
        if args.endpoint_roaming:
            original_pids = [item['process'].pid for item in clients]
            enrollment = (clients[0]['state'] / 'server.json').read_bytes()
            roaming_started = time.monotonic()
            mark('endpoint_roaming_requested')
            # Use the real length-prefixed authenticated daemon protocol, not
            # direct config edits or a fixture-only daemon hook.
            secret = (clients[0]['state'] / '.daemon_secret').read_text().strip()
            message = json.dumps({'secret': secret, 'request': {'ModifyConfig': {
                'public_hostname_ipv4': '192.0.2.12',
                'public_hostname_ipv6': 'fd42:31::12'}}}).encode()
            ns(0, 'ip', 'addr', 'add', '192.0.2.12/24', 'dev', 'eth0')
            ns(0, 'ip', '-6', 'addr', 'add', 'fd42:31::12/64', 'dev', 'eth0', 'nodad')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ipc:
                ipc.settimeout(10)
                ipc.connect(str(tmp / 'client0.sock'))
                ipc.sendall(len(message).to_bytes(4, 'big') + message)
                def receive_exact(size):
                    data = bytearray()
                    while len(data) < size:
                        chunk = ipc.recv(size - len(data))
                        assert chunk, 'daemon IPC response truncated'
                        data.extend(chunk)
                    return bytes(data)
                length = int.from_bytes(receive_exact(4), 'big')
                assert 0 < length <= 65536, 'daemon IPC response exceeded bound'
                response = json.loads(receive_exact(length))
                assert isinstance(response, dict) and 'Ok' in response, 'ModifyConfig failed; private response withheld'
            ns(0, 'ip', 'addr', 'del', '192.0.2.2/24', 'dev', 'eth0')
            ns(0, 'ip', '-6', 'addr', 'del', 'fd42:31::2/64', 'dev', 'eth0')
            affected_links = [link for link in links if node_ids[0] in
                              (link['node_id_peer1'], link['node_id_peer2'])]
            assert len(affected_links) == 2 * (args.nodes - 1)
            def roaming_converged():
                for link in affected_links:
                    remote_node = link['node_id_peer2'] if link['node_id_peer1'] == node_ids[0] else link['node_id_peer1']
                    index = node_indices[remote_node]
                    interface = interfaces[index][tunnel_ids[index].index(link['id'])]
                    rows = ns(index, 'wg', 'show', interface, 'endpoints').splitlines()
                    prefix = '[fd42:31::12]:' if link['ipv6'] else '192.0.2.12:'
                    if len(rows) != 1 or not rows[0].split()[1].startswith(prefix):
                        return None
                    # Exact per-tunnel cache evidence excludes automatic source
                    # learning as the sole explanation for endpoint convergence.
                    cache = json.loads((clients[index]['state'] / 'topology-cache.json').read_bytes())
                    cached = next((tunnel for tunnel in cache['snapshot']['tunnels']
                                   if tunnel['tunnel_id'] == link['id']), None)
                    if not cached or cached['peer_node_id'] != node_ids[0] or not cached['remote_endpoint'].startswith(prefix):
                        return None
                current = inventory()
                by_id = {link['id']: link for link in current['tunnels']}
                for link in affected_links:
                    endpoint_key = 'endpoint_peer1' if link['node_id_peer1'] == node_ids[0] else 'endpoint_peer2'
                    prefix = '[fd42:31::12]:' if link['ipv6'] else '192.0.2.12:'
                    if not by_id[link['id']][endpoint_key].startswith(prefix):
                        return None
                return current
            baseline = eventually(roaming_converged, 'advertised endpoint roaming did not converge')
            last_roaming_ages = None
            roaming_fresh_clients = set()
            def roaming_freshness():
                nonlocal last_roaming_ages
                ages = authenticated_ages()
                if ages != last_roaming_ages:
                    print(json.dumps({'roaming_snapshot_ages_seconds': ages}), flush=True)
                    last_roaming_ages = ages
                if not ages:
                    return None
                for index, age in enumerate(ages):
                    if age <= 5 and age < time.monotonic() - roaming_started:
                        roaming_fresh_clients.add(index)
                if len(roaming_fresh_clients) != len(clients):
                    return None
                return ages
            roaming_ages = eventually(roaming_freshness, 'clients lack fresh authenticated snapshots after roaming')
            eventually(lambda: devices() == interfaces, 'roaming changed mapped interfaces or failed cache convergence')
            roaming_path = eventually(traffic, 'bidirectional traffic failed after endpoint roaming')
            assert roaming_path['public_keys'] == baseline_path['public_keys']
            current_enrollment = json.loads((clients[0]['state'] / 'server.json').read_bytes())
            original_enrollment = json.loads(enrollment)
            for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                        'controller_encryption_key', 'control_network_id', 'wg_private_key'):
                assert current_enrollment.get(key) == original_enrollment.get(key), 'roaming changed enrolled identity'
            assert [item['process'].pid for item in clients] == original_pids
            assert all(item['process'].poll() is None for item in clients)
            baseline_path = roaming_path
            mark('endpoint_roaming_verified')
            roaming_report = {'scope': 'direct dual-stack reference underlay; not NAT traversal',
                'authenticated_modify_config': True, 'old_addresses_removed': True,
                'peer_endpoint_and_authenticated_cache_converged': True,
                'client_processes_and_wireguard_identities_preserved': True,
                'affected_tunnel_ids': [link['id'] for link in affected_links],
                'affected_links': len(affected_links), 'tested_links': roaming_path['tested_links'],
                'controller_snapshot_age_seconds': roaming_ages,
                'measured_verification_seconds': time.monotonic() - roaming_started,
                'bidirectional_traffic': True}
        soak_report = None
        if args.reference_soak:
            # Reference-staging acceptance only: not a production availability SLO.
            streams = []
            original_clients = [item['process'].pid for item in clients]
            started = time.monotonic()
            for slot in range(2):
                for index in range(2):
                    output = cleanup.enter_context((tmp / f'soak-{slot}-{index}.log').open('w+b'))
                    command = ['ip', 'netns', 'exec', f'drill{index}', 'ping', '-n',
                               '-c', '300', '-i', '0.2', '-W', '1', '-I',
                               interfaces[index][slot], f'198.18.{slot}.{2 - index}']
                    probe = subprocess.Popen(command, stdout=output, stderr=output,
                                             env=dict(os.environ, LC_ALL='C'))
                    cleanup.callback(stop, probe)
                    streams.append((slot, index, probe, output))
            time.sleep(max(0, started + 20 - time.monotonic()))
            stop(process)
            assert process.poll() is not None
            outage_started = time.monotonic()
            time.sleep(max(0, started + 30 - time.monotonic()))
            restart_started = time.monotonic()
            process = start_server()
            api('login', credentials)
            soak_ages = []
            def soak_reconnected():
                ages = []
                for index in range(2):
                    status = ns(index, args.client, '--config', tmp / f'client{index}.toml', 'status')
                    match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                    if not match:
                        return False
                    age = int(match[1])
                    # A cached pre-outage snapshot cannot satisfy this test.
                    if age > 5 or age >= time.monotonic() - restart_started:
                        return False
                    ages.append(age)
                current = inventory()
                if current['tunnels'] != baseline['tunnels']:
                    return False
                soak_ages[:] = ages
                return True
            remaining = 15 - (time.monotonic() - restart_started)
            assert remaining > 0, 'reference controller startup exceeded 15 seconds'
            eventually(soak_reconnected, 'reference controller reconnection timeout', timeout=remaining)
            reconciled = time.monotonic()
            assert reconciled - restart_started <= 15, 'reference reconciliation exceeded 15 seconds'
            time.sleep(max(0, started + 60 - time.monotonic()))
            measurements = []
            for slot, index, probe, output in streams:
                code = probe.wait(timeout=5)
                assert code in (0, 1), 'reference ping failed; private output withheld'
                output.seek(0)
                raw = output.read(131073)
                assert len(raw) <= 131072, 'reference ping output exceeded bound'
                text = raw.decode('ascii', errors='replace')
                summary = re.search(r'(\d+) packets transmitted, (\d+) received', text)
                assert summary, 'reference ping summary missing'
                sent, received = map(int, summary.groups())
                assert sent == 300 and 0 <= received <= sent
                replies = ping_replies(text, sent, received)
                longest = streak = 0
                for seq in range(1, sent + 1):
                    streak = 0 if seq in replies else streak + 1
                    longest = max(longest, streak)
                loss = 100 * (sent - received) / sent
                interruption = longest * 0.2
                measurements.append({'link': slot, 'source_client': index,
                    'transmitted': sent, 'received': received, 'loss_percent': loss,
                    'max_missing_probe_interval_seconds': interruption})
            assert [item['process'].pid for item in clients] == original_clients
            assert all(item['process'].poll() is None for item in clients)
            assert devices() == interfaces, 'reference interface identities changed'
            soak_report = {'scope': 'REFERENCE STAGING ONLY; not a production SLO',
                'duration_seconds': time.monotonic() - started,
                'controller_unavailable_until_ready_seconds': reconciled - outage_started,
                'restart_reconciliation_seconds': reconciled - restart_started,
                'controller_snapshot_age_seconds': soak_ages,
                'thresholds': {'loss_percent_per_stream': 1,
                    'max_missing_probe_interval_seconds': 2, 'restart_reconciliation_seconds': 15},
                'measurement': '300 probes per stream at 0.2s; missing-sequence intervals, not sub-probe outage detection',
                'streams': measurements}
            # Emit only numeric measurements before acceptance checks, so a
            # failed run retains evidence even after temporary logs are removed.
            print(json.dumps({'reference_soak_measurements': soak_report}), flush=True)
            assert all(row['loss_percent'] <= 1 for row in measurements), 'reference packet loss exceeded 1 percent'
            assert all(row['max_missing_probe_interval_seconds'] <= 2 for row in measurements), 'reference missing-probe interval exceeded 2 seconds'
        offline_report = None
        if args.offline_client_restart:
            stop(process)
            assert process.poll() is not None
            def controller_unreachable():
                assert process.poll() is not None, 'controller restarted during offline recovery'
                for endpoint in [('127.0.0.1', backend), ('192.0.2.1', control)]:
                    with socket.socket() as sock:
                        sock.settimeout(0.5)
                        assert sock.connect_ex(endpoint) != 0, 'controller reachable during offline recovery'
            controller_unreachable()
            expected_interfaces = [list(names) for names in interfaces]
            enrollments = [(item['state'] / 'server.json').read_bytes() for item in clients]
            old_pids = [item['process'].pid for item in clients]
            for index, item in enumerate(clients):
                stop(item['process'])
                assert item['process'].poll() is not None
                remaining = set(ns(index, 'wg', 'show', 'interfaces').split())
                assert remaining <= set(expected_interfaces[index]), 'unexpected WireGuard interface; refusing cleanup'
                # These names were observed in this fresh namespace before stop.
                # Remove leftovers to prove cache reconstruction, not persistence.
                for interface in sorted(remaining):
                    ns(index, 'ip', 'link', 'del', interface)
                assert not ns(index, 'wg', 'show', 'interfaces').split()
            fresh = int(time.time())
            for index, item in enumerate(clients):
                assert (item['state'] / 'server.json').read_bytes() == enrollments[index]
                start_client(index)
                assert item['process'].pid != old_pids[index]
            interfaces = eventually(devices, 'offline cached interface reconstruction timeout')
            assert interfaces == expected_interfaces, 'offline reconstruction changed interface set'
            offline_path = eventually(lambda: traffic(fresh), 'offline fresh handshake/bidirectional traffic timeout')
            assert offline_path['public_keys'] == baseline_path['public_keys'], 'offline recovery changed WireGuard identities'
            controller_unreachable()
            for index, item in enumerate(clients):
                assert item['process'].poll() is None
                assert (item['state'] / 'server.json').read_bytes() == enrollments[index]
                status = ns(index, args.client, '--config', tmp / f'client{index}.toml', 'status')
                assert re.search(r'Controller Snapshot Age Seconds: Unknown\b', status), 'offline restart claimed controller freshness'
            restart_started = time.monotonic()
            process = start_server()
            api('login', credentials)
            offline_ages = []
            def offline_reconnected():
                ages = []
                for index in range(2):
                    status = ns(index, args.client, '--config', tmp / f'client{index}.toml', 'status')
                    match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                    if not match:
                        return False
                    age = int(match[1])
                    if age > 5 or age >= time.monotonic() - restart_started:
                        return False
                    ages.append(age)
                offline_ages[:] = ages
                return True
            eventually(offline_reconnected, 'offline-recovered clients did not reconnect')
            assert devices() == expected_interfaces
            offline_report = {'scope': 'offline cache recovery, NOT revocation evidence',
                'controller_unreachable_during_reconstruction': True,
                'offline_controller_snapshot_age': 'Unknown',
                'fresh_cached_path': offline_path,
                'reconnected_controller_snapshot_age_seconds': offline_ages}
        damaged_cache_report = None
        if args.damaged_cache_repair:
            repair_indices = range(2) if args.nodes == 2 else (0,)
            original_pids = [item['process'].pid for item in clients]
            expected_interfaces = [list(names) for names in interfaces]
            expected_live_ports = [
                {interface: int(ns(index, 'wg', 'show', interface, 'listen-port').strip())
                 for interface in expected_interfaces[index]} for index in range(args.nodes)]
            originals = {}
            for index in repair_indices:
                item = clients[index]
                stop(item['process'])
                assert item['process'].poll() is not None
                remaining = set(ns(index, 'wg', 'show', 'interfaces').split())
                assert remaining <= set(expected_interfaces[index]), 'unexpected interface; refusing damaged-cache cleanup'
                for interface in sorted(remaining):
                    ns(index, 'ip', 'link', 'del', interface)
                assert not ns(index, 'wg', 'show', 'interfaces').split()
                cache_path = item['state'] / 'topology-cache.json'
                cache_bytes = cache_path.read_bytes()
                cache = json.loads(cache_bytes)
                journal_bytes = (item['state'] / 'topology-revision.json').read_bytes()
                journal = json.loads(journal_bytes)
                assert journal['version'] == 2 and journal['snapshot_hash']
                assert journal['revision'] == cache['snapshot']['revision']
                assert journal['ports'] == cache['ports'] and cache['ports']
                assert journal['identity'] == cache['identity']
                backup = tmp / f'original-cache-{index}.json'
                with open(backup, 'xb', opener=lambda path, flags: os.open(path, flags, 0o600)) as saved:
                    saved.write(cache_bytes)
                originals[index] = {'cache': cache, 'journal': journal_bytes,
                                    'enrollment': (item['state'] / 'server.json').read_bytes()}
                # Only the disposable cache is changed; journals and enrollment
                # retain their authenticated revision/hash/port commitments.
                cache_path.write_bytes(b'damaged topology cache\n')
            fresh = int(time.time())
            repair_started = time.monotonic()
            for index in repair_indices:
                start_client(index)
            repair_ages = []
            def cache_repaired():
                ages = []
                for index in repair_indices:
                    item = clients[index]
                    assert item['process'].poll() is None, 'client exited during cache repair'
                    status = ns(index, args.client, '--config', tmp / f'client{index}.toml', 'status')
                    match = re.search(r'Controller Snapshot Age Seconds: (\d+)\b', status)
                    if not match or int(match[1]) > 5 or int(match[1]) >= time.monotonic() - repair_started:
                        return False
                    try:
                        recovered = json.loads((item['state'] / 'topology-cache.json').read_bytes())
                    except (OSError, ValueError):
                        return False
                    assert recovered == originals[index]['cache'], 'repair changed committed snapshot, identity or ports'
                    assert (item['state'] / 'topology-revision.json').read_bytes() == originals[index]['journal'], 'repair changed revision journal'
                    assert (item['state'] / 'server.json').read_bytes() == originals[index]['enrollment'], 'repair changed enrollment'
                    ages.append(int(match[1]))
                repair_ages[:] = ages
                return True
            eventually(cache_repaired, 'matching authenticated snapshot did not repair damaged cache')
            interfaces = eventually(devices, 'repaired cache interface reconciliation timeout')
            assert interfaces == expected_interfaces
            repaired_path = eventually(traffic, 'repaired cache traffic timeout')
            for path in repaired_path['links']:
                if any(index in repair_indices for index in path['client_indices']):
                    assert all(timestamp >= fresh for timestamp in path['handshakes']), 'repaired tunnel lacks fresh handshake'
            assert repaired_path['public_keys'] == baseline_path['public_keys']
            for index, item in enumerate(clients):
                actual_ports = {interface: int(ns(index, 'wg', 'show', interface, 'listen-port').strip())
                                for interface in interfaces[index]}
                assert actual_ports == expected_live_ports[index], 'repair changed observed listening-port mapping'
                assert item['process'].poll() is None, 'client exited during cache repair'
                if index not in repair_indices:
                    assert item['process'].pid == original_pids[index], 'unaffected client restarted'
            damaged_cache_report = {'scope': 'matching authenticated snapshot repair; no revision lowering',
                'repaired_clients': len(repair_indices), 'repaired_client_indices': list(repair_indices),
                'journal_unchanged': True, 'ports_and_identities_preserved': True,
                'unaffected_clients_not_restarted': True,
                'controller_snapshot_age_seconds': repair_ages, 'fresh_path': repaired_path,
                'cache_sha256': [hashlib.sha256((item['state'] / 'topology-cache.json').read_bytes()).hexdigest()
                                 for item in clients]}
        stop(process)
        assert process.poll() is not None
        mark('backup_controller_stopped')
        mark('snapshot_last_observed_committed_state')
        def snapshot(source, destination):
            with contextlib.closing(sqlite3.connect(source)) as src, contextlib.closing(sqlite3.connect(destination)) as dst:
                src.backup(dst)
                assert dst.execute('PRAGMA integrity_check').fetchone() == ('ok',)
                dst.commit()
            os.chmod(destination, 0o600)
        snapshot(db, tmp / 'backup.db')
        mark('backup_copy_complete')
        subprocess.run(['openssl', 'cms', '-encrypt', '-binary', '-aes-256-cbc',
            '-in', str(tmp / 'backup.db'), '-outform', 'DER',
            '-out', str(tmp / 'backup.cms'), str(tmp / 'tls.pem')], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['openssl', 'cms', '-decrypt', '-binary', '-inform', 'DER',
            '-in', str(tmp / 'backup.cms'), '-recip', str(tmp / 'tls.pem'),
            '-inkey', str(tmp / 'tls.key'), '-out', str(tmp / 'verified-copy.db')],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        mark('ephemeral_test_key_decryption_complete')
        digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        assert digest(tmp / 'backup.db') == digest(tmp / 'verified-copy.db')
        mark('local_second_copy_verified_NOT_off_host')
        for item in clients:
            shutil.copytree(item['state'], tmp / (item['state'].name + '-preserved'))
        process = start_server()
        api('login', credentials)
        before_invites = {x['id'] for x in baseline['invites']}
        api('invites', {'max_uses': 1, 'expires_at': None, 'join_mesh': None})
        mark('post_backup_invite_acknowledged')
        changed = inventory()
        assert len(changed['invites']) == len(baseline['invites']) + 1
        assert changed['tunnels'] == baseline['tunnels']
        mark('simulated_disruption')
        stop(process)
        assert process.poll() is not None
        # No supervisor or other writer exists in this private namespace. Fence the
        # old listener by process death before replacing the self-contained DB.
        for endpoint in [('127.0.0.1', backend), ('192.0.2.1', control)]:
            with socket.socket() as sock:
                assert sock.connect_ex(endpoint) != 0, 'old controller still reachable'
        mark('old_controller_fenced')
        for i, item in enumerate(clients):
            stop(item['process'])
            item['enrollment'] = (item['state'] / 'server.json').read_bytes()
            for interface in ns(i, 'wg', 'show', 'interfaces').split():
                ns(i, 'ip', 'link', 'del', interface)
        # All controller writers are fenced. Let SQLite checkpoint and retire its
        # own sidecars; never discard a WAL or unlink a live SQLite sidecar.
        with contextlib.closing(sqlite3.connect(db)) as conn:
            busy, remaining, checkpointed = conn.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            assert busy == 0 and remaining == checkpointed, 'stopped database checkpoint failed'
            assert conn.execute('PRAGMA integrity_check').fetchone() == ('ok',)
        for suffix in ('-wal', '-shm', '-journal'):
            assert not Path(str(db) + suffix).exists(), 'SQLite sidecar remains; refusing restore'
        shutil.copy2(tmp / 'verified-copy.db', db)
        assert digest(db) == digest(tmp / 'backup.db')
        mark('restore_installed')
        process = start_server()
        api('login', credentials)
        restored = inventory()
        def stable(value):
            value = json.loads(json.dumps(value))
            for node in value['nodes']:
                node.pop('last_seen', None)
            for key in value:
                if isinstance(value[key], list):
                    value[key].sort(key=lambda row: json.dumps(row, sort_keys=True))
            return value
        assert stable(restored) == stable(baseline), 'restored inventory differs'
        assert {x['id'] for x in restored['invites']} == before_invites
        fresh = int(time.time())
        for i, item in enumerate(clients):
            assert (item['state'] / 'server.json').read_bytes() == item['enrollment']
            start_client(i)
        interfaces = eventually(devices, 'restored client reconciliation timeout')
        restored_path = eventually(lambda: traffic(fresh), 'fresh handshake/bidirectional traffic timeout')
        assert restored_path['public_keys'] == baseline_path['public_keys'], 'WireGuard identities changed'
        for item in clients:
            current = json.loads((item['state'] / 'server.json').read_text())
            previous = json.loads(item['enrollment'])
            for key in ('control_node_id', 'controller_peer_id', 'controller_signing_key',
                        'controller_encryption_key', 'control_network_id', 'control_private_key',
                        'control_encryption_private_key', 'wg_private_key'):
                assert current[key] == previous[key], f'enrollment identity changed: {key}'
        # No last_seen assertion: the controller does not update that legacy field.
        # Fresh daemon memory starts Unknown; only an authenticated Snapshot RPC,
        # signature/decryption, revision/cache validation and refresh restore set it.
        snapshot_ages = eventually(authenticated_ages, 'same enrolled clients did not reconnect')
        restored_resources = resources()
        mark('service_restored')
        revocation_report = None
        if args.offline_revocation:
            assert shutil.which('nft'), '--offline-revocation requires nftables'
            isolated = clients[0]
            isolated_enrollment = (isolated['state'] / 'server.json').read_bytes()
            isolated_cache = (isolated['state'] / 'topology-cache.json').read_bytes()
            node_id = json.loads(isolated_enrollment)['control_node_id']
            expected = [list(names) for names in interfaces]
            # Restart only the isolated client to discard existing TCP sessions
            # and in-memory freshness while preserving its enrolled cache.
            ns(0, 'nft', 'add', 'table', 'inet', 'revocation_drill')
            ns(0, 'nft', 'add', 'chain', 'inet', 'revocation_drill', 'output',
               '{ type filter hook output priority 0; policy accept; }')
            ns(0, 'nft', 'add', 'rule', 'inet', 'revocation_drill', 'output',
               'ip', 'daddr', '192.0.2.1', 'tcp', 'dport', str(control), 'reject')
            stop(isolated['process'])
            assert isolated['process'].poll() is not None
            remaining = set(ns(0, 'wg', 'show', 'interfaces').split())
            assert remaining <= set(expected[0]), 'unexpected isolated interface; refusing cleanup'
            for interface in sorted(remaining):
                ns(0, 'ip', 'link', 'del', interface)
            fresh = int(time.time())
            start_client(0)
            interfaces = eventually(devices, 'isolated cached tunnel reconstruction timeout')
            assert interfaces == expected
            eventually(lambda: traffic(fresh), 'control-isolated cached traffic failed before revocation')
            status = ns(0, args.client, '--config', tmp / 'client0.toml', 'status')
            assert re.search(r'Controller Snapshot Age Seconds: Unknown\b', status)
            api('actions', {'action': 'delete_node', 'id': node_id})
            revoked_ids = {link['id'] for link in links if node_id in
                           (link['node_id_peer1'], link['node_id_peer2'])}
            survivor_links = [(slot, link) for slot, link in enumerate(links)
                              if link['id'] not in revoked_ids]
            survivor_names = [set() for _ in clients]
            for index in range(1, args.nodes):
                survivor_names[index] = {expected[index][slot] for slot, tunnel_id in enumerate(tunnel_ids[index])
                                         if tunnel_id not in revoked_ids}
            def reachable_peer_removed():
                for index in range(1, args.nodes):
                    current = set(ns(index, 'wg', 'show', 'interfaces').split())
                    assert current <= set(expected[index]), 'unexpected reachable-peer interface'
                    if current != survivor_names[index]:
                        return False
                    cache = json.loads((clients[index]['state'] / 'topology-cache.json').read_bytes())
                    expected_ids = set(tunnel_ids[index]) - revoked_ids
                    if {tunnel['tunnel_id'] for tunnel in cache['snapshot']['tunnels']} != expected_ids:
                        return False
                    if set(map(int, cache['ports'])) != expected_ids:
                        return False
                return True
            eventually(reachable_peer_removed, 'reachable peer retained revoked WireGuard resources')
            assert ns(0, 'wg', 'show', 'interfaces').split()
            assert (isolated['state'] / 'topology-cache.json').read_bytes() == isolated_cache
            assert (isolated['state'] / 'server.json').read_bytes() == isolated_enrollment
            def revoked_traffic_denied():
                for slot, link in enumerate(links):
                    if link['id'] not in revoked_ids:
                        continue
                    interface = expected[0][tunnel_ids[0].index(link['id'])]
                    denied = subprocess.run(['ip', 'netns', 'exec', 'drill0', 'ping', '-n',
                        '-c', '3', '-W', '1', '-I', interface, f'198.18.{slot}.2'],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    assert denied.returncode == 1, 'revoked cached peer still passed traffic (or ping failed operationally)'
            revoked_traffic_denied()
            def survivor_traffic():
                paths = [traffic_pair(link, slot) for slot, link in survivor_links]
                if not all(paths):
                    return None
                for path in paths:
                    original = next(row for row in restored_path['links'] if row['tunnel_id'] == path['tunnel_id'])
                    assert path['public_keys'] == original['public_keys'], 'revocation changed survivor identities'
                return {'tested_links': len(paths), 'links': paths, 'bidirectional_ping': True}
            survivors_before_reconnect = eventually(survivor_traffic, 'unrelated survivor traffic failed after revocation')
            log_offset = (tmp / 'client0.log').stat().st_size
            ns(0, 'nft', 'delete', 'table', 'inet', 'revocation_drill')
            def rejected_after_reconnect():
                status = ns(0, args.client, '--config', tmp / 'client0.toml', 'status')
                assert re.search(r'Controller Snapshot Age Seconds: Unknown\b', status), 'revoked identity obtained successful freshness'
                with (tmp / 'client0.log').open('rb') as log_input:
                    log_input.seek(log_offset)
                    evidence = log_input.read(262145)
                assert len(evidence) <= 262144, 'revocation diagnostic output exceeded bound'
                return b'control snapshot sync failed: unknown control identity' in evidence
            eventually(rejected_after_reconnect, 'revoked enrolled identity did not receive controller rejection')
            assert reachable_peer_removed(), 'revoked resources returned after reconnect'
            revoked_traffic_denied()
            survivors_after_reconnect = eventually(survivor_traffic, 'survivor traffic failed after revoked client reconnect')
            assert (isolated['state'] / 'topology-cache.json').read_bytes() == isolated_cache
            assert (isolated['state'] / 'server.json').read_bytes() == isolated_enrollment
            revocation_report = {'scope': 'direct reference topology; not NAT traversal or global offline erasure',
                'reachable_peer_wireguard_resources_removed': True,
                'isolated_client_retained_cached_intent': True,
                'traffic_to_reachable_peer_blocked': True,
                'revoked_tunnel_ids': sorted(revoked_ids),
                'reachable_peers_verified': args.nodes - 1,
                'survivor_paths_before_reconnect': survivors_before_reconnect,
                'survivor_paths_after_reconnect': survivors_after_reconnect,
                'reconnected_identity_rejected': True, 'revoked_controller_snapshot_age': 'Unknown'}
        # Ages establish control reconnection separately from cached data traffic.
        print(json.dumps({'result': 'PASS', 'events_unix_seconds': events,
            'nodes': args.nodes,
            'measurement_scope': 'disposable direct dual-stack full mesh; not 80-node capacity or mixed-production-traffic evidence',
            'baseline_controller_snapshot_age_seconds': baseline_ages,
            'resource_measurements': {'baseline': baseline_resources, 'restored': restored_resources,
                'scope': 'Linux process RSS/high-water RSS samples; excludes kernel WireGuard memory'},
            'reconnected_controller_snapshot_age_seconds': snapshot_ages,
            'reference_soak': soak_report,
            'reference_mixed_traffic': mixed_traffic_report,
            'offline_client_restart': offline_report,
            'damaged_cache_repair': damaged_cache_report,
            'offline_revocation': revocation_report,
            'endpoint_roaming': roaming_report,
            'client_crash_recovery': crash_report,
            'client_binary_upgrade': upgrade_report,
            'client_package_reinstall': reinstall_report,
            'packaged_client_crash_recovery': packaged_crash_report,
            'baseline_inventory_counts': {key: len(value) for key, value in baseline.items() if isinstance(value, list)},
            'baseline_node_ids': [node['id'] for node in baseline['nodes']],
            'controller_peer_id': peer,
            'baseline_path': baseline_path, 'restored_path': restored_path,
            'lost_changes': ['one unused unrelated invitation'],
            'lost_write_window_seconds': events['post_backup_invite_acknowledged'] - events['snapshot_last_observed_committed_state'],
            'measured_recovery_seconds': events['service_restored'] - events['simulated_disruption'],
            'omitted_intervals': ['detection', 'notification', 'off-host transfer/verification', 'key retrieval'],
            'objective_met': 'NOT CLAIMED', 'older_backup_safety': 'NOT CLAIMED'}, indent=2))


if __name__ == '__main__':
    main()
