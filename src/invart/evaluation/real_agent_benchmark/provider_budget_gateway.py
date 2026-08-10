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


GATEWAY_RECORD_SCHEMA_VERSION = "invart.provider_budget_gateway_record.v0.2"


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
        require_command_scope: bool = False,
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
        self._scope_lock = threading.Lock()
        self._require_command_scope = bool(require_command_scope)
        self._active_command_scope: dict[str, Any] | None = None
        budget_ledger.validate_scope(manifest=manifest)

    def begin_command_scope(
        self,
        *,
        command_id: str,
        maximum_calls: int,
        maximum_total_tokens: int,
    ) -> dict[str, Any]:
        normalized_command_id = str(command_id or "").strip()
        if not normalized_command_id:
            raise ValueError("gateway command scope requires a command ID")
        call_limit = int(maximum_calls)
        token_limit = int(maximum_total_tokens)
        if call_limit <= 0 or token_limit <= 0:
            raise ValueError("gateway command scope limits must be positive")
        with self._scope_lock:
            if self._active_command_scope is not None:
                raise RuntimeError("gateway command scope is already active")
            self._active_command_scope = {
                "command_id": normalized_command_id,
                "maximum_calls": call_limit,
                "maximum_total_tokens": token_limit,
                "calls_reserved": 0,
                "tokens_reserved": 0,
            }
            return dict(self._active_command_scope)

    def end_command_scope(self, *, command_id: str) -> dict[str, Any]:
        normalized_command_id = str(command_id or "").strip()
        with self._scope_lock:
            scope = self._active_command_scope
            if scope is None:
                raise RuntimeError("gateway command scope is not active")
            if scope["command_id"] != normalized_command_id:
                raise RuntimeError("gateway command scope ID mismatch")
            self._active_command_scope = None
            return dict(scope)

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
            completion_count = request_payload.get("n", 1)
            if type(completion_count) is not int or completion_count != 1:
                raise ValueError("gateway supports exactly one completion per request")
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
        maximum_token_fields = (
            "max_tokens",
            "max_completion_tokens",
            "max_output_tokens",
        )
        supplied_token_fields = [
            field_name
            for field_name in maximum_token_fields
            if field_name in request_payload
        ]
        if not supplied_token_fields:
            request_payload["max_tokens"] = maximum_tokens
        elif token_limit_clamped:
            for field_name in maximum_token_fields:
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
        try:
            reservation, command_scope_id = self._reserve_budget(
                maximum_tokens=maximum_tokens,
                request_id=gateway_request_id,
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
                    "command_scope_id": self._current_command_scope_id(),
                    "stream_requested": bool(request_payload.get("stream")),
                    "message_count": len(messages),
                    "request_fields": sorted(str(key) for key in request_payload),
                    "maximum_tokens": maximum_tokens,
                    "reason": str(exc),
                    "budget_reserved": False,
                }
            )
            raise
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
            "command_scope_id": command_scope_id,
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
            response_body = b"".join(upstream.chunks)
            response_hash = "sha256:" + hashlib.sha256(response_body).hexdigest()
            assistant_evidence = _assistant_response_evidence(
                content_type=upstream.content_type,
                response_body=response_body,
            )
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
                "command_scope_id": command_scope_id,
                "forwarded_request_hash": stable_json_hash(request_payload),
                "response_hash": response_hash,
                **assistant_evidence,
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
                "command_scope_id": command_scope_id,
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

    def _reserve_budget(
        self,
        *,
        maximum_tokens: int,
        request_id: str,
    ) -> tuple[dict[str, Any], str | None]:
        with self._scope_lock:
            scope = self._active_command_scope
            if self._require_command_scope and scope is None:
                raise RuntimeError("gateway command scope is required")
            if scope is not None:
                if int(scope["calls_reserved"]) >= int(scope["maximum_calls"]):
                    raise RuntimeError("gateway command call budget exhausted")
                if (
                    int(scope["tokens_reserved"]) + maximum_tokens
                    > int(scope["maximum_total_tokens"])
                ):
                    raise RuntimeError("gateway command token budget exhausted")
            reservation = self.budget_ledger.reserve(
                manifest=self.manifest,
                maximum_tokens=maximum_tokens,
                request_id=request_id,
            )
            if scope is None:
                return reservation, None
            scope["calls_reserved"] = int(scope["calls_reserved"]) + 1
            scope["tokens_reserved"] = int(scope["tokens_reserved"]) + maximum_tokens
            return reservation, str(scope["command_id"])

    def _current_command_scope_id(self) -> str | None:
        with self._scope_lock:
            if self._active_command_scope is None:
                return None
            return str(self._active_command_scope["command_id"])

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
    if len(supplied) > 1:
        raise ValueError("gateway request has multiple maximum token fields")
    value = supplied[0] if supplied else default
    maximum = int(value)
    if maximum <= 0:
        raise ValueError("gateway maximum tokens must be positive")
    return maximum


def _assistant_response_evidence(
    *,
    content_type: str,
    response_body: bytes,
) -> dict[str, Any]:
    payloads = (
        _server_sent_event_payloads(response_body)
        if "text/event-stream" in content_type.lower()
        else _json_response_payloads(response_body)
    )
    fragments: list[dict[str, Any]] = []
    for payload in payloads:
        choices = payload.get("choices")
        if not isinstance(choices, list):
            continue
        for choice in choices:
            if not isinstance(choice, Mapping):
                continue
            fragment = choice.get("message")
            if not isinstance(fragment, Mapping):
                fragment = choice.get("delta")
            if isinstance(fragment, Mapping):
                fragments.append(dict(fragment))
    return {
        "assistant_message_observed": bool(fragments),
        "assistant_nonempty": any(_assistant_fragment_nonempty(item) for item in fragments),
        "assistant_message_hash": stable_json_hash(
            {"assistant_fragments": fragments}
        ),
    }


def _json_response_payloads(response_body: bytes) -> list[Mapping[str, Any]]:
    try:
        payload = json.loads(response_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    return [payload] if isinstance(payload, Mapping) else []


def _server_sent_event_payloads(response_body: bytes) -> list[Mapping[str, Any]]:
    payloads: list[Mapping[str, Any]] = []
    try:
        response = response_body.decode("utf-8")
    except UnicodeDecodeError:
        return payloads
    for line in response.splitlines():
        if not line.startswith("data:"):
            continue
        data = line.removeprefix("data:").strip()
        if not data or data == "[DONE]":
            continue
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, Mapping):
            payloads.append(payload)
    return payloads


def _assistant_fragment_nonempty(fragment: Mapping[str, Any]) -> bool:
    content = fragment.get("content")
    if isinstance(content, str) and bool(content.strip()):
        return True
    if isinstance(content, list) and any(
        (
            isinstance(item, str)
            and bool(item.strip())
        )
        or (
            isinstance(item, Mapping)
            and any(
                isinstance(item.get(field_name), str)
                and bool(str(item[field_name]).strip())
                for field_name in ("text", "content")
            )
        )
        for item in content
    ):
        return True
    return any(
        bool(fragment.get(field_name))
        for field_name in ("tool_calls", "function_call")
    )


class _RejectRedirects(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib_error.HTTPError(
            req.full_url,
            code,
            "provider gateway redirects are forbidden",
            headers,
            fp,
        )


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
        opener = urllib_request.build_opener(_RejectRedirects())
        with opener.open(request, timeout=timeout) as response:
            chunks = tuple(iter(lambda: response.read(65536), b""))
            return GatewayUpstreamResponse(
                status=int(response.status),
                content_type=str(response.headers.get("Content-Type") or "application/json"),
                chunks=chunks,
            )
    except urllib_error.HTTPError as exc:
        raise RuntimeError(f"provider gateway upstream failed: HTTP {exc.code}") from exc
    except Exception as exc:
        raise RuntimeError(f"provider gateway upstream failed: {type(exc).__name__}") from exc


__all__ = [
    "GatewayForwardResult",
    "GatewayUpstreamResponse",
    "ProviderBudgetGateway",
    "start_provider_budget_gateway",
]
