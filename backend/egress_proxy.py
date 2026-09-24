#!/usr/bin/env python3
"""CONNECT-only egress allowlist proxy (Phase 4 execution infrastructure,
docs/decisiones.md D-077 follow-up).

WHY: a worker container needs to reach exactly one thing - the
configured LLM API host - and nothing else (docs/decisiones.md's Phase 4
audit explicitly rejected "a vague hostname-only allowlist" living
INSIDE the container, since anything running in that container could
trivially ignore its own promise). The enforcement point has to be
OUTSIDE the container's control: this proxy runs on the HOST (or as its
own separate, dual-homed container - see backend/worker_supervisor.py),
and the worker container is given NO direct route to the internet at
all (--network set to a Docker network with no default gateway) except
to this proxy's own address, via HTTPS_PROXY. The proxy is the only
thing that can actually reach the real internet, and it enforces the
allowlist on every single CONNECT target before opening a tunnel -
refusing anything not explicitly allowed, with no code path in the
worker that can widen this.

CONNECT-only, deliberately: an LLM API call is always HTTPS, which a
client reaches through an HTTP proxy via the CONNECT method (the proxy
never sees the decrypted request, only host:port) - so CONNECT is the
only method this proxy needs to support at all. Any other method
(GET/POST/...) is refused outright, closing off plain-HTTP egress
entirely rather than trying to filter it.

Standard library only. No credentials pass through this module - it
never inspects the TLS payload it tunnels, only the CONNECT target.
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Set, Tuple

CONNECT_TIMEOUT_SECONDS = 10
TUNNEL_IDLE_TIMEOUT_SECONDS = 120
_BUFFER_SIZE = 65536


def _relay(source: socket.socket, destination: socket.socket) -> None:
    try:
        while True:
            chunk = source.recv(_BUFFER_SIZE)
            if not chunk:
                break
            destination.sendall(chunk)
    except OSError:
        pass  # either side closed/reset - expected at tunnel teardown, never a reason to crash the proxy.
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def make_proxy_handler(allowed_targets: Set[Tuple[str, int]]) -> type:
    """allowed_targets is a set of exact (hostname, port) pairs - never a
    substring/suffix/wildcard match, so "api.anthropic.com.evil.example"
    or a same-suffix sibling host can never pass. Returns a fresh
    handler class per call, same "never module-level globals" discipline
    backend/http_app.py's make_handler() already established, so
    multiple proxy instances (e.g. one per test) never share state."""

    class ProxyHandler(BaseHTTPRequestHandler):
        server_version = "backend-egress-proxy/2026.1"

        def do_CONNECT(self) -> None:
            host, _, port_text = self.path.rpartition(":")
            try:
                port = int(port_text)
            except ValueError:
                self.send_error(400, "malformed CONNECT target")
                self.close_connection = True
                return
            if (host, port) not in allowed_targets:
                self.send_error(403, "target not allowed by egress policy")
                self.close_connection = True
                return
            try:
                upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT_SECONDS)
            except OSError:
                self.send_error(502, "could not reach upstream target")
                self.close_connection = True
                return
            self.send_response(200, "Connection Established")
            self.end_headers()
            client_sock = self.connection
            client_sock.settimeout(TUNNEL_IDLE_TIMEOUT_SECONDS)
            upstream.settimeout(TUNNEL_IDLE_TIMEOUT_SECONDS)
            forward = threading.Thread(target=_relay, args=(client_sock, upstream), daemon=True)
            forward.start()
            _relay(upstream, client_sock)
            forward.join(timeout=CONNECT_TIMEOUT_SECONDS)
            upstream.close()
            self.close_connection = True

        def _refuse_non_connect(self) -> None:
            # No egress at all for anything that isn't a CONNECT tunnel -
            # see module docstring on why CONNECT is the only supported method.
            self.send_error(405, "only CONNECT is supported by this proxy")
            self.close_connection = True

        def do_GET(self) -> None:
            self._refuse_non_connect()

        def do_POST(self) -> None:
            self._refuse_non_connect()

        def do_PUT(self) -> None:
            self._refuse_non_connect()

        def do_DELETE(self) -> None:
            self._refuse_non_connect()

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass  # never logs the CONNECT target verbatim by default - see run_egress_proxy()'s own docstring on why.

    return ProxyHandler


def run_egress_proxy(allowed_targets: Set[Tuple[str, int]], host: str = "0.0.0.0", port: int = 0) -> ThreadingHTTPServer:
    """Starts the proxy. host defaults to 0.0.0.0 (unlike backend/
    http_app.py's 127.0.0.1 default) because worker containers on an
    isolated Docker network reach this proxy over that network's
    interface, not loopback - the isolation boundary here is the Docker
    network + allowed_targets, not which interface this process binds."""
    handler_cls = make_proxy_handler(allowed_targets)
    return ThreadingHTTPServer((host, port), handler_cls)
