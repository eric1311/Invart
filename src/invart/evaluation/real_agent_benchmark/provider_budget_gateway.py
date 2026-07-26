from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib import error as urllib_error
from urllib import request as urllib_request

from invart.core.artifacts import stable_json_hash
from invart.core.models import utc_now

from .agent_runtime_manifest import RuntimeManifest
from .provider_credentials import redact_provider_secrets
from .provider_run_control import ProviderBudgetLedger


GATEWAY_RECORD_SCHEMA_VERSION = "invart.provider_budget_gateway_record.v0.1"


@dataclass(frozen=True)
class GatewayUpstreamResponse:
    status: int
    content_type: str
    chunks: tuple[bytes, ...]


@dataclass(frozen=True)
class GatewayForwardResult:
    status: int
    content_type: str
    chunks: tuple[bytes, ...]
    record: dict[str, Any]


GatewayTransport = Callable[..., GatewayUpstreamResponse]


def reconcile_gateway_records(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    materialized = [dict(record) for record in records]
    pending_ids = {
        str(record.get("gateway_request_id"))
        for record in materialized
        if record.get("status") == "reserved_pending"
        and record.get("gateway_request_id")
    }
    terminal = [
        record
        for record in materialized
        if record.get("status")
        in {
            "forwarded",
            "transport_failed",
            "rejected_before_reservation",
            "rejected_client_authentication",
        }
    ]
    terminal_ids = {
        str(record.get("gateway_request_id"))
        for record in terminal
        if record.get("gateway_request_id")
    }
    all_ids = {
        str(record.get("gateway_request_id"))
        for record in materialized
        if record.get("gateway_request_id")
    }
    ingress_without_id = sum(
        1
        for record in materialized
        if record.get("status")
        in {"rejected_before_reservation", "rejected_client_authentication"}
        and not record.get("gateway_request_id")
    )
    pending_without_terminal = pending_ids - terminal_ids
    terminal_without_pending = terminal_ids - pending_ids
    return {
        "schema_version": "invart.provider_gateway_reconciliation.v0.1",
        "records": len(materialized),
        "ingress_count": len(all_ids) + ingress_without_id,
        "forwarded_count": sum(
            1 for record in terminal if record.get("status") == "forwarded"
        ),
        "terminal_error_count": sum(
            1
            for record in terminal
            if record.get("status")
            in {
                "transport_failed",
                "rejected_before_reservation",
                "rejected_client_authentication",
            }
        ),
        "pending_request_ids": sorted(pending_ids),
        "terminal_request_ids": sorted(terminal_ids),
        "pending_without_terminal_request_ids": sorted(pending_without_terminal),
        "terminal_without_pending_request_ids": sorted(terminal_without_pending),
        "orphan_request_ids": sorted(
            pending_without_terminal | terminal_without_pending
        ),
    }


class ProviderBudgetGateway:
    """Loopback-only OpenAI-compatible gateway with approval-bound reservations."""

    def __init__(
        self,
        *,
        manifest: RuntimeManifest,
        budget_ledger: ProviderBudgetLedger,
        environment: Mapping[str, str],
        log_path: Path,
        maximum_tokens_per_call: int,
        timeout: float = 120.0,
        transport: GatewayTransport | None = None,
    ) -> None:
        profile = manifest.provider_profile
        if profile is None:
            raise ValueError("provider budget gateway requires a provider profile")
        if maximum_tokens_per_call <= 0:
            raise ValueError("maximum_tokens_per_call must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        secret = str(environment.get(profile.credential_env_name) or "")
        if not secret:
            raise RuntimeError(
                f"required gateway provider credential is missing: {profile.credential_env_name}"
            )
        self.manifest = manifest
        self.budget_ledger = budget_ledger
        self._secret = secret
        self.log_path = log_path.expanduser().absolute()
        self.maximum_tokens_per_call = int(maximum_tokens_per_call)
        self.timeout = float(timeout)
        self._transport = transport or _urllib_gateway_transport
        self._record_lock = threading.Lock()
        budget_ledger.validate_scope(manifest=manifest)

    def models_payload(self) -> dict[str, Any]:
        return {
            "object": "list",
            "data": [
                {
                    "id": self.manifest.request.requested_model,
                    "object": "model",
                    "owned_by": self.manifest.request.requested_provider,
                }
            ],
        }

    def forward(self, payload: Mapping[str, Any]) -> GatewayForwardResult:
        request_payload = dict(payload)
        request_hash = stable_json_hash(request_payload)
        requested_model = str(request_payload.get("model") or "")
        expected_model = self.manifest.request.requested_model
        messages = request_payload.get("messages")
        try:
            if requested_model != expected_model:
                raise ValueError("gateway request model does not match approved manifest")
            if not isinstance(messages, list):
                raise ValueError("gateway request requires a messages list")
            requested_maximum_tokens = _requested_maximum_tokens(
                request_payload,
                default=self.maximum_tokens_per_call,
            )
        except (RuntimeError, ValueError) as exc:
            self._append_record(
                {
                    "schema_version": GATEWAY_RECORD_SCHEMA_VERSION,
                    "recorded_at": utc_now(),
                    "status": "rejected_before_reservation",
                    "provider": self.manifest.request.requested_provider,
                    "requested_model": requested_model,
                    "expected_model": expected_model,
                    "manifest_hash": self.manifest.manifest_hash,
                    "request_hash": request_hash,
                    "stream_requested": bool(request_payload.get("stream")),
                    "message_count": len(messages) if isinstance(messages, list) else None,
                    "request_fields": sorted(str(key) for key in request_payload),
                    "maximum_token_fields": {
                        key: request_payload.get(key)
                        for key in ("max_tokens", "max_completion_tokens", "max_output_tokens")
                        if key in request_payload
                    },
                    "reason": str(exc),
                    "budget_reserved": False,
                }
            )
            raise

        maximum_tokens = min(requested_maximum_tokens, self.maximum_tokens_per_call)
        token_limit_clamped = requested_maximum_tokens > maximum_tokens
        if token_limit_clamped:
            for field_name in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
                if field_name in request_payload:
                    request_payload[field_name] = maximum_tokens
        initiated_at = utc_now()
        gateway_request_id = stable_json_hash(
            {
                "request_hash": request_hash,
                "initiated_at": initiated_at,
                "thread_id": threading.get_ident(),
            }
        )
        reservation = self.budget_ledger.reserve(
            manifest=self.manifest,
            maximum_tokens=maximum_tokens,
            request_id=gateway_request_id,
        )
        profile = self.manifest.provider_profile
        if profile is None:  # pragma: no cover - constructor invariant
            raise RuntimeError("gateway provider profile unavailable")
        started_at = utc_now()
        pending_record = {
            "schema_version": GATEWAY_RECORD_SCHEMA_VERSION,
            "recorded_at": started_at,
            "started_at": initiated_at,
            "status": "reserved_pending",
            "gateway_request_id": gateway_request_id,
            "provider": profile.profile_id,
            "model": expected_model,
            "manifest_hash": self.manifest.manifest_hash,
            "request_hash": request_hash,
            "forwarded_request_hash": stable_json_hash(request_payload),
            "stream_requested": bool(request_payload.get("stream")),
            "message_count": len(messages),
            "request_fields": sorted(str(key) for key in request_payload),
            "maximum_tokens": maximum_tokens,
            "requested_maximum_tokens": requested_maximum_tokens,
            "token_limit_clamped": token_limit_clamped,
            "budget_reservation": reservation,
        }
        self._append_record(pending_record)
        try:
            upstream = self._transport(
                url=profile.base_url.rstrip("/") + "/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._secret}",
                    "Content-Type": "application/json",
                },
                body=json.dumps(request_payload, ensure_ascii=False, separators=(",", ":")),
                timeout=self.timeout,
            )
            if not isinstance(upstream, GatewayUpstreamResponse):
                raise RuntimeError("gateway transport returned an invalid response")
            response_hash = "sha256:" + hashlib.sha256(b"".join(upstream.chunks)).hexdigest()
            record = {
                "schema_version": GATEWAY_RECORD_SCHEMA_VERSION,
                "recorded_at": utc_now(),
                "started_at": started_at,
                "status": "forwarded",
                "gateway_request_id": gateway_request_id,
                "provider": profile.profile_id,
                "model": expected_model,
                "manifest_hash": self.manifest.manifest_hash,
                "request_hash": request_hash,
                "forwarded_request_hash": stable_json_hash(request_payload),
                "response_hash": response_hash,
                "stream_requested": bool(request_payload.get("stream")),
                "message_count": len(messages),
                "request_fields": sorted(str(key) for key in request_payload),
                "maximum_tokens": maximum_tokens,
                "requested_maximum_tokens": requested_maximum_tokens,
                "token_limit_clamped": token_limit_clamped,
                "budget_reservation": reservation,
                "upstream_status": upstream.status,
                "content_type": upstream.content_type,
                "claim_boundary": (
                    "This record proves an approval-bound provider request was forwarded. It does not "
                    "prove native-agent task success or benchmark grading."
                ),
            }
            self._append_record(record)
            return GatewayForwardResult(
                status=upstream.status,
                content_type=upstream.content_type,
                chunks=upstream.chunks,
                record=record,
            )
        except Exception as exc:
            record = {
                "schema_version": GATEWAY_RECORD_SCHEMA_VERSION,
                "recorded_at": utc_now(),
                "started_at": started_at,
                "status": "transport_failed",
                "gateway_request_id": gateway_request_id,
                "provider": profile.profile_id,
                "model": expected_model,
                "manifest_hash": self.manifest.manifest_hash,
                "request_hash": request_hash,
                "stream_requested": bool(request_payload.get("stream")),
                "message_count": len(messages),
                "request_fields": sorted(str(key) for key in request_payload),
                "maximum_tokens": maximum_tokens,
                "requested_maximum_tokens": requested_maximum_tokens,
                "token_limit_clamped": token_limit_clamped,
                "budget_reservation": reservation,
                "error_type": type(exc).__name__,
            }
            self._append_record(record)
            raise

    def record_client_authentication_rejection(self, *, method: str, path: str) -> None:
        self._append_record(
            {
                "schema_version": GATEWAY_RECORD_SCHEMA_VERSION,
                "recorded_at": utc_now(),
                "status": "rejected_client_authentication",
                "provider": self.manifest.request.requested_provider,
                "model": self.manifest.request.requested_model,
                "manifest_hash": self.manifest.manifest_hash,
                "method": str(method),
                "path": str(path),
                "budget_reserved": False,
                "reason": "missing_or_invalid_client_bearer",
            }
        )

    def _append_record(self, record: Mapping[str, Any]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.log_path.parent.chmod(0o700)
        encoded = json.dumps(dict(record), ensure_ascii=False, sort_keys=True)
        encoded = redact_provider_secrets(encoded, secret_values=(self._secret,))
        with self._record_lock:
            descriptor = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, (encoded + "\n").encode("utf-8"))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)


def start_provider_budget_gateway(
    *,
    gateway: ProviderBudgetGateway,
    client_bearer_token: str,
    host: str = "127.0.0.1",
    port: int = 0,
) -> tuple[ThreadingHTTPServer, threading.Thread, int]:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("provider budget gateway must bind to loopback")
    expected_authorization = _client_authorization(client_bearer_token)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path.rstrip("/") == "/v1/models":
                if not self._authenticate_client():
                    return
                self._write_json(gateway.models_payload())
                return
            self.send_error(404)

        def do_POST(self) -> None:  # noqa: N802
            if self.path.rstrip("/") != "/v1/chat/completions":
                self.send_error(404)
                return
            if not self._authenticate_client():
                return
            try:
                length = int(self.headers.get("Content-Length") or "0")
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("request body must be a JSON object")
                result = gateway.forward(payload)
            except (RuntimeError, ValueError) as exc:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": type(exc).__name__, "message": str(exc)}).encode("utf-8")
                )
                return
            self.send_response(result.status)
            self.send_header("Content-Type", result.content_type)
            self.end_headers()
            try:
                for chunk in result.chunks:
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                # The provider request has already reached a terminal gateway
                # state. A caller (notably OpenCode's background title request)
                # may abandon the response after upstream completion, so avoid
                # turning that client-delivery event into a server traceback.
                return

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _write_json(self, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _authenticate_client(self) -> bool:
            supplied = str(self.headers.get("Authorization") or "")
            if hmac.compare_digest(supplied.encode("utf-8"), expected_authorization):
                return True
            gateway.record_client_authentication_rejection(
                method=self.command,
                path=self.path,
            )
            encoded = json.dumps(
                {
                    "error": "Unauthorized",
                    "message": "missing or invalid gateway client bearer",
                }
            ).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(encoded)
            return False

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = False
    server.block_on_close = True
    actual_port = int(server.server_address[1])
    thread = threading.Thread(
        target=server.serve_forever,
        name="invart-provider-budget-gateway",
        daemon=True,
    )
    thread.start()
    return server, thread, actual_port


def _client_authorization(client_bearer_token: str) -> bytes:
    token = str(client_bearer_token)
    if len(token) < 24 or token.strip() != token or any(character.isspace() for character in token):
        raise ValueError("gateway client bearer token must be at least 24 non-whitespace characters")
    return f"Bearer {token}".encode("utf-8")


def _requested_maximum_tokens(payload: Mapping[str, Any], *, default: int) -> int:
    values = [
        payload.get("max_tokens"),
        payload.get("max_completion_tokens"),
        payload.get("max_output_tokens"),
    ]
    supplied = [value for value in values if value is not None]
    if len(supplied) > 1 and len({int(value) for value in supplied}) > 1:
        raise ValueError("gateway request has conflicting maximum token fields")
    value = supplied[0] if supplied else default
    maximum = int(value)
    if maximum <= 0:
        raise ValueError("gateway maximum tokens must be positive")
    return maximum


def _urllib_gateway_transport(
    *,
    url: str,
    headers: Mapping[str, str],
    body: str,
    timeout: float,
) -> GatewayUpstreamResponse:
    request = urllib_request.Request(
        url,
        data=body.encode("utf-8"),
        headers=dict(headers),
        method="POST",
    )
    try:
        with urllib_request.urlopen(request, timeout=timeout) as response:
            chunks = tuple(iter(lambda: response.read(65536), b""))
            return GatewayUpstreamResponse(
                status=int(response.status),
                content_type=str(response.headers.get("Content-Type") or "application/json"),
                chunks=chunks,
            )
    except urllib_error.HTTPError as exc:
        body_bytes = exc.read()
        raise RuntimeError(f"provider gateway upstream failed: HTTP {exc.code}") from exc
    except Exception as exc:
        raise RuntimeError(f"provider gateway upstream failed: {type(exc).__name__}") from exc


__all__ = [
    "GatewayForwardResult",
    "GatewayUpstreamResponse",
    "ProviderBudgetGateway",
    "start_provider_budget_gateway",
]
