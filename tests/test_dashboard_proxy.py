#!/usr/bin/env python3
"""Live TLS-terminated dashboard reverse-proxy test using Caddy in Docker."""

import base64
import os
import pathlib
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dashboard  # noqa: E402


CADDY_IMAGE = os.environ.get("CADDY_TEST_IMAGE", "caddy:2-alpine")


def free_tcp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(url, context, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, context=context, timeout=3) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.headers, response.read()


def docker_output(command, timeout=30):
    return subprocess.run(
        command,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
    ).stdout


def run():
    docker = shutil.which("docker")
    if not docker:
        message = "Docker Engine is required for the live Caddy HTTPS proxy test."
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            raise RuntimeError(message)
        print("SKIP: " + message)
        return 0

    token = secrets.token_urlsafe(48)
    app = dashboard.create_server(0, host="0.0.0.0", auth_token=token)
    app_thread = threading.Thread(target=app.serve_forever, daemon=True)
    app_thread.start()

    proxy_port = free_tcp_port()
    container_name = "ghidra-dashboard-caddy-test-" + secrets.token_hex(4)
    temporary = tempfile.TemporaryDirectory(prefix="ghidra-dashboard-caddy-")
    temp_path = pathlib.Path(temporary.name)
    root_cert = temp_path / "caddy-local-root.crt"
    try:
        production_config = (REPO_ROOT / "deploy/caddy/Caddyfile").read_text(
            encoding="utf-8"
        )
        for required in (
            "header_up -Forwarded",
            "header_up -X-Forwarded-For",
            "header_up -X-Forwarded-Host",
            "header_up -X-Forwarded-Proto",
        ):
            if required not in production_config:
                raise AssertionError("Caddy config is missing: " + required)
        if "header_up -Authorization" in production_config:
            raise AssertionError("Caddy must not remove the Basic Authorization header.")

        test_config = production_config.replace(
            "ghidra-report:8080", f"host.docker.internal:{app.server_port}"
        )
        if test_config == production_config:
            raise AssertionError("Could not substitute the test dashboard upstream.")
        config_path = temp_path / "Caddyfile"
        config_path.write_text(test_config, encoding="utf-8")
        data_path = temp_path / "data"
        config_state_path = temp_path / "config"
        data_path.mkdir()
        config_state_path.mkdir()

        docker_output([
            docker, "run", "--detach", "--name", container_name,
            "--add-host=host.docker.internal:host-gateway",
            "--publish", f"127.0.0.1:{proxy_port}:443",
            "--env", "DASHBOARD_DOMAIN=localhost",
            "--volume", f"{config_path}:/etc/caddy/Caddyfile:ro",
            "--volume", f"{data_path}:/data",
            "--volume", f"{config_state_path}:/config",
            CADDY_IMAGE,
        ], timeout=180)

        url = f"https://localhost:{proxy_port}/"
        unverified_context = ssl._create_unverified_context()
        deadline = time.monotonic() + 60
        ready = False
        last_status = None
        while time.monotonic() < deadline:
            try:
                last_status, _headers, _body = request(url, unverified_context)
                if last_status == 401:
                    ready = True
                    break
            except (OSError, ssl.SSLError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        if not ready:
            logs = subprocess.run(
                [docker, "logs", container_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            ).stdout
            raise RuntimeError(
                f"Caddy did not proxy to the dashboard (last status: {last_status}).\n{logs}"
            )

        docker_output([
            docker, "cp",
            f"{container_name}:/data/caddy/pki/authorities/local/root.crt",
            str(root_cert),
        ])
        trusted_context = ssl.create_default_context(cafile=str(root_cert))

        status, headers, body = request(url, trusted_context)
        assert status == 401, f"unauthenticated request returned {status}"
        assert headers.get("WWW-Authenticate", "").startswith("Basic ")
        assert headers.get("Strict-Transport-Security", "").startswith("max-age=")
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("Referrer-Policy") == "no-referrer"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Cache-Control") == "no-store"
        assert b"Authentication required" in body

        authorization = "Basic " + base64.b64encode(
            ("ghidra-report:" + token).encode("utf-8")
        ).decode("ascii")
        status, headers, body = request(
            url,
            trusted_context,
            headers={
                "Authorization": authorization,
                "Forwarded": "for=198.51.100.77;proto=http",
                "X-Forwarded-For": "198.51.100.77",
                "X-Forwarded-Host": "attacker.example",
                "X-Forwarded-Proto": "http",
            },
        )
        assert status == 200, f"valid Basic credentials returned {status}"
        assert b"Threat Intelligence Dashboard" in body
        assert headers.get("Content-Security-Policy"), "dashboard CSP was lost at the proxy"
        assert headers.get("Cache-Control") == "no-store"

        wrong_authorization = "Basic " + base64.b64encode(
            ("ghidra-report:" + ("x" * 64)).encode("utf-8")
        ).decode("ascii")
        status, _headers, _body = request(
            url, trusted_context, headers={"Authorization": wrong_authorization}
        )
        assert status == 401, f"invalid Basic credentials returned {status}"

        print(
            "PASS: Caddy terminated TLS, retained the dashboard Basic-auth challenge, "
            "forwarded valid Authorization, rejected invalid credentials, and preserved "
            "dashboard security headers."
        )
        return 0
    finally:
        subprocess.run(
            [docker, "rm", "--force", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        app.shutdown()
        app.server_close()
        app_thread.join(timeout=3)
        temporary.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise
