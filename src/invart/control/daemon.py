from __future__ import annotations

import fcntl
import json
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

from invart.core.models import RuntimeEvent, utc_now
from invart.control.runtime import close_session, record_action, record_approval, record_outcome, start_session
from invart.surfaces.corpus import capability_events_from_corpus
from invart.governance.profiles import policy_mode_from_profile
from invart.governance.identity import validate_session_identity


DAEMON_SCHEMA_VERSION = "invart.daemon.v0.3"
SESSION_STATES = {"active", "paused", "interrupted", "stopped", "deleted"}
CLOSED_STATES = {"stopped", "deleted"}


@dataclass
class RegistrySession:
    session_id: str
    status: str
    target: str
    agent: str | None
    goal: str | None
    ledger_path: str
    created_at: str
    updated_at: str
    started_at: str | None = None
    stopped_at: str | None = None
    last_heartbeat_at: str | None = None
    last_activity_at: str | None = None
    last_decision_id: str | None = None
    last_invocation_id: str | None = None
    last_risk: str | None = None
    last_effect: str | None = None
    last_approval_grade: str | None = None
    pending_approvals: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RegistrySession":
        return cls(
            session_id=str(payload["session_id"]),
            status=str(payload.get("status", "active")),
            target=str(payload.get("target", "")),
            agent=payload.get("agent"),
            goal=payload.get("goal"),
            ledger_path=str(payload.get("ledger_path", "")),
            created_at=str(payload.get("created_at", utc_now())),
            updated_at=str(payload.get("updated_at", utc_now())),
            started_at=payload.get("started_at"),
            stopped_at=payload.get("stopped_at"),
            last_heartbeat_at=payload.get("last_heartbeat_at"),
            last_activity_at=payload.get("last_activity_at"),
            last_decision_id=payload.get("last_decision_id"),
            last_invocation_id=payload.get("last_invocation_id"),
            last_risk=payload.get("last_risk"),
            last_effect=payload.get("last_effect"),
            last_approval_grade=payload.get("last_approval_grade"),
            pending_approvals=[str(item) for item in payload.get("pending_approvals", [])],
            metadata=dict(payload.get("metadata") or {}),
        )


def default_authority_dir(target: Path) -> Path:
    return target.expanduser().resolve() / ".invart" / "daemon"


def default_state_path(target: Path) -> Path:
    return default_authority_dir(target) / "state.json"


class RuntimeAuthority:
    def __init__(self, state_path: Path):
        self.state_path = state_path.expanduser().resolve()
        self.lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")

    @classmethod
    def for_target(cls, target: Path) -> "RuntimeAuthority":
        return cls(default_state_path(target))

    def init(self) -> dict[str, Any]:
        with self._locked_state() as state:
            state.setdefault("schema_version", DAEMON_SCHEMA_VERSION)
            state.setdefault("authority_id", f"auth_{uuid.uuid4().hex[:12]}")
            state.setdefault("created_at", utc_now())
            state["updated_at"] = utc_now()
            state.setdefault("sessions", {})
            return self._public_state(state)

    def status(self) -> dict[str, Any]:
        state = self._load_state()
        sessions = state.get("sessions", {}) if isinstance(state.get("sessions"), dict) else {}
        by_status: dict[str, int] = {}
        for session in sessions.values():
            if not isinstance(session, dict):
                continue
            status = str(session.get("status", "unknown"))
            by_status[status] = by_status.get(status, 0) + 1
        return {
            **self._public_state(state),
            "state_path": str(self.state_path),
            "sessions_total": len(sessions),
            "sessions_by_status": by_status,
        }

    def create_session(
        self,
        target: Path,
        agent: str | None = None,
        goal: str | None = None,
        session_id: str | None = None,
        ledger_path: Path | None = None,
        preflight_path: Path | None = None,
        create_preflight: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> RegistrySession:
        validate_session_identity(agent, metadata)
        self.init()
        session = start_session(
            target,
            ledger_path=ledger_path,
            agent=agent,
            goal=goal,
            session_id=session_id,
            preflight_path=preflight_path,
            create_preflight=create_preflight,
        )
        now = utc_now()
        registry = RegistrySession(
            session_id=session.session_id,
            status="active",
            target=session.target,
            agent=session.agent,
            goal=session.goal,
            ledger_path=session.ledger_path,
            created_at=session.started_at,
            updated_at=now,
            started_at=session.started_at,
            last_heartbeat_at=now,
            last_activity_at=now,
            metadata=dict(metadata or {}),
        )
        with self._locked_state() as state:
            sessions = self._sessions(state)
            sessions[registry.session_id] = registry.to_dict()
            state["updated_at"] = now
        return registry

    def list_sessions(self, include_deleted: bool = False) -> list[dict[str, Any]]:
        state = self._load_state()
        sessions = [RegistrySession.from_dict(item).to_dict() for item in self._sessions(state).values()]
        if not include_deleted:
            sessions = [item for item in sessions if item.get("status") != "deleted"]
        return sorted(sessions, key=lambda item: str(item.get("updated_at", "")), reverse=True)

    def get_session(self, session_id: str) -> RegistrySession:
        state = self._load_state()
        payload = self._sessions(state).get(session_id)
        if not isinstance(payload, dict):
            raise ValueError(f"session not found: {session_id}")
        return RegistrySession.from_dict(payload)

    def transition_session(self, session_id: str, status: str, reason: str | None = None) -> RegistrySession:
        if status not in SESSION_STATES:
            raise ValueError(f"unknown session status: {status}")
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            if registry.status in CLOSED_STATES and status not in {"deleted"}:
                raise ValueError(f"session is closed: {session_id}")
            now = utc_now()
            registry.status = status
            registry.updated_at = now
            registry.last_activity_at = now
            if status == "active":
                registry.last_heartbeat_at = now
                if registry.started_at is None:
                    registry.started_at = now
            if status in {"stopped", "deleted"}:
                registry.stopped_at = registry.stopped_at or now
            if reason:
                registry.metadata = dict(registry.metadata)
                registry.metadata["last_transition_reason"] = reason
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = now
        if status == "stopped":
            try:
                close_session(Path(registry.ledger_path), status="closed")
            except Exception as exc:  # registry transition should preserve the failure for inspection
                registry.metadata = dict(registry.metadata)
                registry.metadata["close_error"] = str(exc)
                with self._locked_state() as state:
                    self._sessions(state)[session_id] = registry.to_dict()
        return registry

    def heartbeat(self, session_id: str, actor: str | None = None) -> RegistrySession:
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            self._ensure_writable(registry)
            now = utc_now()
            registry.last_heartbeat_at = now
            registry.last_activity_at = now
            registry.updated_at = now
            if actor:
                registry.metadata = dict(registry.metadata)
                registry.metadata["last_heartbeat_actor"] = actor
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = now
            return registry

    def record_event(
        self,
        session_id: str,
        payload: dict[str, Any],
        *,
        review_mode: str = "auto",
        policy_mode: str = "advisory",
        reviewer: str = "heuristic",
        policy_profile: str | None = None,
        policy_profile_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            self._ensure_writable(registry)
            event_payload = dict(payload)
            event_payload.setdefault("session_id", session_id)
            event = RuntimeEvent.from_dict(event_payload)
            profile_config = policy_profile_config or _profile_config_from_registry(registry)
            effective_policy_mode = policy_mode_from_profile(profile_config, policy_mode)
            action, decision, taint = record_action(
                event,
                Path(registry.ledger_path),
                review_mode=review_mode,
                policy_mode=effective_policy_mode,
                reviewer=reviewer,
                policy_profile=policy_profile,
                policy_profile_config=profile_config,
            )
            now = utc_now()
            registry.last_activity_at = now
            registry.updated_at = now
            registry.last_decision_id = decision.decision_id
            registry.last_invocation_id = action.invocation_id or action.event_id
            registry.last_risk = decision.risk
            registry.last_effect = decision.effect
            if decision.requires_approval and decision.decision_id not in registry.pending_approvals:
                registry.pending_approvals.append(decision.decision_id)
            if not decision.requires_approval and decision.decision_id in registry.pending_approvals:
                registry.pending_approvals.remove(decision.decision_id)
            registry.last_approval_grade = "require_human" if decision.requires_approval else ("blocked" if decision.effect == "deny" else "auto_approve")
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = now
            return {
                "recorded": True,
                "session": registry.to_dict(),
                "event": action.to_dict(),
                "decision": decision.to_dict(),
                "taint": taint.to_dict(),
            }


    def register_capabilities(
        self,
        session_id: str,
        corpus_root: Path,
        *,
        adapter: str = "unknown",
        review_mode: str = "off",
        policy_mode: str = "managed",
        reviewer: str = "heuristic",
        policy_profile: str | None = None,
        policy_profile_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        events = capability_events_from_corpus(corpus_root, session_id=session_id, adapter=adapter)
        grants: list[dict[str, Any]] = []
        for event_payload in events:
            grants.append(
                self.record_event(
                    session_id,
                    event_payload,
                    review_mode=review_mode,
                    policy_mode=policy_mode,
                    reviewer=reviewer,
                    policy_profile=policy_profile,
                    policy_profile_config=policy_profile_config,
                )
            )
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            surfaces = []
            for grant in grants:
                event = dict(grant.get("event") or {})
                metadata = dict(event.get("metadata") or {})
                surface = dict(metadata.get("capability_surface") or {})
                surfaces.append(
                    {
                        "grant_id": metadata.get("capability_grant_id"),
                        "source_id": surface.get("source_id"),
                        "kind": surface.get("kind"),
                        "capabilities": surface.get("capabilities", []),
                        "risk": grant.get("decision", {}).get("risk"),
                        "effect": grant.get("decision", {}).get("effect"),
                        "decision_id": grant.get("decision", {}).get("decision_id"),
                    }
                )
            registry.metadata = dict(registry.metadata)
            registry.metadata["capability_grants"] = surfaces
            registry.metadata["capability_corpus_root"] = str(corpus_root)
            registry.metadata["capability_adapter"] = adapter
            registry.updated_at = utc_now()
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = registry.updated_at
        return {
            "registered": True,
            "session": self.get_session(session_id).to_dict(),
            "grants": grants,
            "summary": {
                "total": len(grants),
                "pending_approvals": len(self.get_session(session_id).pending_approvals),
            },
        }

    def approve(self, session_id: str, decision_id: str, status: str, approver: str | None = None, reason: str | None = None) -> dict[str, Any]:
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            self._ensure_known(registry)
            profile_config = _profile_config_from_registry(registry)
            if status == "approved" and _local_approval_disabled(profile_config):
                registry.updated_at = utc_now()
                registry.last_activity_at = registry.updated_at
                registry.metadata = dict(registry.metadata)
                registry.metadata["last_approval_block"] = {
                    "decision_id": decision_id,
                    "reason": "profile disables local approval overrides",
                    "actor": approver,
                    "requested_status": status,
                }
                self._sessions(state)[session_id] = registry.to_dict()
                state["updated_at"] = registry.updated_at
                return {"approval_blocked": True, "reason": "profile disables local approval overrides", "session": registry.to_dict()}
            approval = record_approval(Path(registry.ledger_path), decision_id, status, approver=approver, reason=reason)
            if decision_id in registry.pending_approvals:
                registry.pending_approvals.remove(decision_id)
            registry.updated_at = utc_now()
            registry.last_activity_at = registry.updated_at
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = registry.updated_at
            return {"approval": approval.to_dict(), "session": registry.to_dict()}

    def outcome(
        self,
        session_id: str,
        status: str,
        decision_id: str | None = None,
        invocation_id: str | None = None,
        actor: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        with self._locked_state() as state:
            registry = self._get_session_from_state(state, session_id)
            self._ensure_known(registry)
            outcome = record_outcome(
                Path(registry.ledger_path),
                status,
                decision_id=decision_id,
                invocation_id=invocation_id,
                actor=actor,
                reason=reason,
            )
            registry.updated_at = utc_now()
            registry.last_activity_at = registry.updated_at
            self._sessions(state)[session_id] = registry.to_dict()
            state["updated_at"] = registry.updated_at
            return {"outcome": outcome.to_dict(), "session": registry.to_dict()}

    @contextmanager
    def _locked_state(self) -> Iterator[dict[str, Any]]:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("w", encoding="utf-8") as lock_handle:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            state = self._load_state_unlocked()
            state.setdefault("schema_version", DAEMON_SCHEMA_VERSION)
            state.setdefault("authority_id", f"auth_{uuid.uuid4().hex[:12]}")
            state.setdefault("created_at", utc_now())
            state.setdefault("updated_at", utc_now())
            state.setdefault("sessions", {})
            yield state
            self._write_state_unlocked(state)
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

    def _load_state(self) -> dict[str, Any]:
        with self._locked_state() as state:
            return json.loads(json.dumps(state, ensure_ascii=False))

    def _load_state_unlocked(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema_version": DAEMON_SCHEMA_VERSION,
                "authority_id": f"auth_{uuid.uuid4().hex[:12]}",
                "created_at": utc_now(),
                "updated_at": utc_now(),
                "sessions": {},
            }
        try:
            loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {
                "schema_version": DAEMON_SCHEMA_VERSION,
                "authority_id": f"auth_{uuid.uuid4().hex[:12]}",
                "created_at": utc_now(),
                "updated_at": utc_now(),
                "sessions": {},
                "warnings": ["state file could not be parsed; recreated in memory"],
            }
        if not isinstance(loaded, dict):
            loaded = {}
        loaded.setdefault("schema_version", DAEMON_SCHEMA_VERSION)
        loaded.setdefault("authority_id", f"auth_{uuid.uuid4().hex[:12]}")
        loaded.setdefault("created_at", utc_now())
        loaded.setdefault("updated_at", utc_now())
        loaded.setdefault("sessions", {})
        return loaded

    def _write_state_unlocked(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _public_state(self, state: dict[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": state.get("schema_version", DAEMON_SCHEMA_VERSION),
            "authority_id": state.get("authority_id"),
            "created_at": state.get("created_at"),
            "updated_at": state.get("updated_at"),
        }

    def _sessions(self, state: dict[str, Any]) -> dict[str, Any]:
        sessions = state.setdefault("sessions", {})
        if not isinstance(sessions, dict):
            state["sessions"] = {}
        return state["sessions"]

    def _get_session_from_state(self, state: dict[str, Any], session_id: str) -> RegistrySession:
        payload = self._sessions(state).get(session_id)
        if not isinstance(payload, dict):
            raise ValueError(f"session not found: {session_id}")
        return RegistrySession.from_dict(payload)

    def _ensure_known(self, registry: RegistrySession) -> None:
        if registry.status == "deleted":
            raise ValueError(f"session is deleted: {registry.session_id}")

    def _ensure_writable(self, registry: RegistrySession) -> None:
        self._ensure_known(registry)
        if registry.status in {"paused", "interrupted", "stopped"}:
            raise ValueError(f"session is not active: {registry.session_id} ({registry.status})")


__all__ = [
    "DAEMON_SCHEMA_VERSION",
    "RegistrySession",
    "RuntimeAuthority",
    "default_authority_dir",
    "default_state_path",
]


def _profile_config_from_registry(registry: RegistrySession) -> dict[str, Any] | None:
    profile = registry.metadata.get("policy_profile_config") if isinstance(registry.metadata, dict) else None
    return dict(profile) if isinstance(profile, dict) else None


def _local_approval_disabled(profile: dict[str, Any] | None) -> bool:
    if not profile:
        return False
    approval = profile.get("approval") if isinstance(profile.get("approval"), dict) else {}
    if "local_approval" in approval:
        return not bool(approval.get("local_approval"))
    return False
