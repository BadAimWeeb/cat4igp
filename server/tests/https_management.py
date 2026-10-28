#!/usr/bin/env python3
"""Live trusted-TLS smoke check; requires built server and frontend/dist, no packages."""
import base64
import argparse
import contextlib
import copy
import functools
import hashlib
import hmac
import http.client
import http.cookiejar
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def secret_file(path, value):
    with open(path, "x", opener=lambda p, flags: os.open(p, flags, 0o600)) as out:
        json.dump(value, out)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and "src" in attrs:
            self.paths.append(attrs["src"])
        if tag == "link" and attrs.get("rel") == "stylesheet":
            self.paths.append(attrs["href"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", action="store_true", help="also run installed Firefox native BiDi UI assertions")
    args = parser.parse_args()
    binary = ROOT / "target/debug/cat4igp-server"
    dist = ROOT / "frontend/dist"
    assert binary.is_file() and (dist / "index.html").is_file(), "build server and frontend first"
    with TemporaryDirectory(prefix="cat4igp-https-") as directory, contextlib.ExitStack() as cleanup:
        tmp = Path(directory)
        # Secrets and subprocess logs never leave this owner-only temporary directory.
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=tmp, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=cat4igp smoke CA", "-keyout", "ca.key", "-out", "ca.pem",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", "tls.key", "-out", "tls.csr")
        (tmp / "extensions").write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        openssl("x509", "-req", "-in", "tls.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "1", "-extfile", "extensions", "-out", "tls.pem")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(tmp / "tls.pem", tmp / "tls.key")
        backend = [0]
        observations = []  # Only booleans/metadata, never Cookie values or request bodies.

        # ponytail: loopback-only test ingress; use hardened production ingress for deployment.
        class Proxy(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def end_headers(self):
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; "
                                 "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
                                 "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
                super().end_headers()

            def do_GET(self):
                if self.path == "/__observations":
                    data = json.dumps(observations).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif self.path.startswith("/admin/"):
                    self.forward()
                else:
                    super().do_GET()

            def do_POST(self):
                if not self.path.startswith("/admin/"):
                    self.send_error(404)
                    return
                self.forward()

            def forward(self):
                length = self.headers.get("Content-Length", "0")
                if not length.isdecimal() or int(length) > 4096:
                    self.send_error(413)
                    return
                self.connection.settimeout(10)
                body = self.rfile.read(int(length))
                hop = {"connection", "transfer-encoding", "keep-alive", "upgrade",
                       "proxy-authorization", "proxy-authenticate", "te", "trailer"}
                headers = {k: v for k, v in self.headers.items() if k.lower() not in hop}
                conn = http.client.HTTPConnection("127.0.0.1", backend[0], timeout=10)
                try:
                    conn.request(self.command, self.path, body, headers)
                    response = conn.getresponse()
                    data = response.read()
                    if "?cross-site=" in self.path:
                        observations.append({"method": self.command, "path": self.path,
                            "cookie_seen": "__Host-cat4igp=" in self.headers.get("Cookie", ""),
                            "origin": self.headers.get("Origin"), "status": response.status})
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in hop | {"content-length"}:
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                finally:
                    conn.close()

        proxy = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(Proxy, directory=str(dist)))
        proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        origin = f"https://localhost:{proxy.server_port}"
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        def close_proxy():
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=10)
        cleanup.callback(close_proxy)
        if args.browser:
            class CrossSite(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

                def do_GET(self):
                    html = (f'<a href="{origin}/admin/me?cross-site=get">Cross-site GET</a>'
                            f'<form method="post" action="{origin}/admin/login?cross-site=post">'
                            '<button>Cross-site POST</button></form>').encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)

            cross = http.server.ThreadingHTTPServer(("127.0.0.1", 0), CrossSite)
            cross.socket = tls.wrap_socket(cross.socket, server_side=True)
            cross_origin = f"https://127.0.0.1:{cross.server_port}"
            cross_thread = threading.Thread(target=cross.serve_forever, daemon=True)
            cross_thread.start()
            def close_cross():
                cross.shutdown()
                cross.server_close()
                cross_thread.join(timeout=10)
            cleanup.callback(close_cross)
        signing = secrets.token_hex(32)
        credentials = {"username": "administrator", "password": secrets.token_urlsafe(32)}
        secret_file(tmp / "jwt.json", {"origin": origin, "issuer": "smoke",
                    "audience": "browser", "active": "smoke", "keys": {"smoke": signing}})
        secret_file(tmp / "bootstrap.json", credentials)
        ports = []
        for index in range(2):
            listen = port()
            ports.append(listen)
            # Do not inherit cluster/discovery/secret configuration or load repository .env.
            env = {k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ}
            env.update(DATABASE_URL=str(tmp / f"controller-{index}.db"), AUTO_MIGRATE="false",
                       BIND_HOST_PORT=f"127.0.0.1:{listen}",
                       CONTROL_BIND_MULTIADDR="/ip4/127.0.0.1/tcp/0",
                       CONTROL_PRIVATE_NETWORK_KEY="/key/swarm/psk/1.0.0/\n/base16/\n" + secrets.token_hex(32),
                       ADMIN_JWT_CONFIG_FILE=str(tmp / "jwt.json"),
                       ADMIN_BOOTSTRAP_FILE=str(tmp / "bootstrap.json"))
            log = cleanup.enter_context((tmp / f"server-{index}.log").open("wb"))
            subprocess.run([binary, "migrate"], cwd=tmp, env=env, stdout=log, stderr=log, check=True)
            process = subprocess.Popen([binary], cwd=tmp, env=env, stdout=log, stderr=log)
            cleanup.callback(stop, process)
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, "controller failed startup (logs deliberately withheld)"
                try:
                    with socket.create_connection(("127.0.0.1", listen), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "controller startup timeout"
                    threading.Event().wait(0.05)

        backend[0] = ports[0]
        trusted = ssl.create_default_context(cafile=str(tmp / "ca.pem"))
        assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
        with socket.create_connection(("127.0.0.1", proxy.server_port), timeout=10) as sock:
            try:
                trusted.wrap_socket(sock, server_hostname="invalid.example")
            except ssl.SSLCertVerificationError:
                pass
            else:
                raise AssertionError("hostname mismatch accepted")
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.HTTPSHandler(context=trusted),
                                            urllib.request.HTTPCookieProcessor(jar))

        def request(path, expected, body=None, headers=None):
            req = urllib.request.Request(origin + path,
                data=None if body is None else json.dumps(body).encode(), headers=headers or {})
            try:
                response = client.open(req, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                assert response.status == expected, f"{path}: expected {expected}, got {response.status}"
                return response.headers, data

        try:
            urllib.request.urlopen(origin, context=ssl.create_default_context(), timeout=10)
        except urllib.error.URLError as error:
            assert isinstance(error.reason, ssl.SSLCertVerificationError)
        else:
            raise AssertionError("untrusted TLS certificate accepted")
        _, html = request("/", 200)
        assets = Assets()
        assets.feed(html.decode())
        assert assets.paths, "built frontend assets missing"
        for asset in assets.paths:
            assert asset.startswith("/assets/")
            assert request(asset, 200)[1]
        request("/admin/me", 401)
        post = {"Origin": origin, "Content-Type": "application/json"}
        request("/admin/login", 403, credentials, {"Content-Type": "application/json"})
        request("/admin/login", 403, credentials, {**post, "Origin": "https://evil.example"})
        request("/admin/login", 401, {**credentials, "password": secrets.token_urlsafe(32)}, post)
        headers, _ = request("/admin/login", 200, credentials, post)
        cookie = headers["Set-Cookie"]
        assert cookie.startswith("__Host-cat4igp=") and "Domain=" not in cookie
        for flag in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=900"):
            assert flag in cookie, "cookie security attribute missing"
        stored = list(jar)
        assert len(stored) == 1 and stored[0].secure and stored[0].path == "/"
        request("/admin/me", 200)
        request("/admin/me", 401, headers={"Cookie": "__Host-cat4igp=invalid"})
        action = {"action": "create_mesh", "name": "HTTPS smoke", "auto_wireguard": False, "mtu": 1420}
        mutation = {**post, "Idempotency-Key": "https-smoke-mesh"}
        request("/admin/actions", 403, action, {k: v for k, v in mutation.items() if k != "Origin"})
        request("/admin/actions", 403, action, {**mutation, "Origin": "https://evil.example"})
        if args.browser:
            request("/admin/actions", 403, action, {**mutation, "Origin": cross_origin})
            request("/admin/me", 200)
            print("PASS: independent HTTP client with valid session + cross-site Origin JSON action 403; session still 200 (not a browser CORS test)")
        request("/admin/actions", 415, action, {**mutation, "Content-Type": "text/plain"})
        assert not json.loads(request("/admin/inventory", 200)[1])["meshes"]
        first = json.loads(request("/admin/actions", 200, action, mutation)[1])
        assert first["committed"]
        assert json.loads(request("/admin/actions", 200, action, mutation)[1]) == first
        assert len(json.loads(request("/admin/inventory", 200)[1])["meshes"]) == 1
        request("/admin/replicas", 409)
        backend[0] = ports[1]
        request("/admin/me", 200)  # Same cookie, same origin, independent controller process.
        assert not json.loads(request("/admin/inventory", 200)[1])["meshes"]
        request("/admin/status", 200)
        def signed_token(iat, exp):
            def encode(value):
                return base64.urlsafe_b64encode(value).rstrip(b"=")
            header = {"alg": "HS256", "typ": "JWT", "kid": "smoke"}
            claims = {"sub": "administrator:1", "iss": "smoke", "aud": "browser",
                      "iat": iat, "exp": exp}
            payload = b".".join(encode(json.dumps(value).encode()) for value in (header, claims))
            signature = hmac.new(signing.encode(), payload, hashlib.sha256).digest()
            return (payload + b"." + encode(signature)).decode()

        def signed_cookie(iat, exp):
            token_cookie = copy.copy(stored[0])
            token_cookie.value = signed_token(iat, exp)
            # ponytail: keep JWT expiry independent of cookie expiry; test browser enforcement separately.
            token_cookie.expires = None
            token_cookie.discard = True
            jar.clear()
            jar.set_cookie(token_cookie)

        for listen in ports:
            backend[0] = listen
            now = int(time.time())
            signed_cookie(now + 60 - 900, now + 60)
            request("/admin/me", 200)
            before = json.loads(request("/admin/inventory", 200)[1])
            signed_cookie(now - 901, now - 901 + 900)
            request("/admin/me", 401)
            request("/admin/actions", 401, {**action, "name": "Expired JWT must not create"},
                    {**mutation, "Idempotency-Key": "https-smoke-expired"})
            signed_cookie(now + 60 - 900, now + 60)
            assert json.loads(request("/admin/inventory", 200)[1]) == before, "expired JWT mutated inventory"
        jar.clear()
        jar.set_cookie(stored[0])
        request("/admin/logout", 403, {}, {**post, "Origin": "https://evil.example"})
        request("/admin/me", 200)
        headers, _ = request("/admin/logout", 204, {}, post)
        assert "Max-Age=0" in headers["Set-Cookie"] and not list(jar)
        request("/admin/me", 401)
        if args.browser:
            backend[0] = ports[0]
            now = int(time.time())
            secret_file(tmp / "browser.json", {"origin": origin, "cross_origin": cross_origin, **credentials,
                        "expired": signed_token(now - 901, now - 1), "ca": str(tmp / "ca.pem")})
            subprocess.run(["node", ROOT / "server/tests/browser_management.mjs", tmp / "browser.json"],
                           check=True, timeout=120)
        print("PASS: trusted hostname-verified HTTPS; untrusted CA rejected; built frontend assets served")
        print("PASS: login/cookie attributes, invalid JWT, Origin/CSRF/JSON rejection, mutation replay, logout")
        print("PASS: signed HS256 JWT with 60s remaining accepted; signed expired JWT me/action 401, unchanged inventory on both controllers")
        print("LIMIT: synthetic JWT timestamps, not real elapsed 15m expiry")
        print("PASS: one cookie on two independent standalone controllers; isolated DBs, NOT HA; processes cleaned on exit")


if __name__ == "__main__":
    main()