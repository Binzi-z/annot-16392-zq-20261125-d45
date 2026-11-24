"""Tiny append-only JSONL commit log used by the concurrency fault lab."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .engine import (
    AuditEngine,
    AuditEvent,
    DelegationGranted,
    EvidenceRegistered,
    GenerationAdvanced,
    GrantRevoked,
    RootAuthorized,
    SignoffCommitted,
    SignoffRejected,
)

_EVENT_TYPES: dict[str, type[AuditEvent]] = {
    cls.kind: cls  # type: ignore[attr-defined]
    for cls in (
        EvidenceRegistered,
        GenerationAdvanced,
        RootAuthorized,
        DelegationGranted,
        GrantRevoked,
        SignoffCommitted,
        SignoffRejected,
    )
}

_TUPLE_FIELDS = {"case_ids"}


def event_to_dict(event: AuditEvent) -> dict[str, Any]:
    if not is_dataclass(event):
        raise TypeError(f"not an event: {event!r}")
    data = asdict(event)
    data["kind"] = event.kind
    return data


def event_from_dict(data: dict[str, Any]) -> AuditEvent:
    kind = data["kind"]
    cls = _EVENT_TYPES[kind]
    kwargs = {k: v for k, v in data.items() if k != "kind"}
    for field_name in _TUPLE_FIELDS:
        if field_name in kwargs and kwargs[field_name] is not None:
            kwargs[field_name] = tuple(kwargs[field_name])
    return cls(**kwargs)  # type: ignore[return-value]


class DurableEventLog:
    """A fsynced JSONL log.

    The lock is exposed to the service so validation and commit can be
    serialized as one critical section when needed.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.lock = threading.RLock()
        self.records: list[dict[str, Any]] = []
        if self.path is not None and self.path.exists():
            self.records = _read_records(self.path)

    @classmethod
    def create(cls, path: str | Path, *, reset: bool = False) -> "DurableEventLog":
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if reset and path.exists():
            path.unlink()
        return cls(path)

    def append(
        self,
        event: AuditEvent,
        engine: AuditEngine,
        injector: "FaultInjector | None" = None,
        *,
        inject: bool = True,
    ) -> AuditEvent:
        with self.lock:
            seq = len(self.records) + 1
            from dataclasses import replace

            planned = replace(event, seq=seq)  # type: ignore[arg-type]
            if injector is not None and inject:
                injector.before_commit(planned)

            record = event_to_dict(planned)
            line = json.dumps(record, ensure_ascii=False, sort_keys=True)
            if self.path is not None:
                # Open/write/fsync/close makes the commit point explicit and
                # avoids Windows cross-thread file-handle surprises.
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(line + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())

            self.records.append(record)
            assigned_seq = engine.commit(event)
            if assigned_seq != seq:
                raise RuntimeError(
                    f"commit sequence mismatch: log={seq}, engine={assigned_seq}"
                )

            if injector is not None and inject:
                injector.after_commit(planned)
            return planned

    def read_all(self) -> list[dict[str, Any]]:
        with self.lock:
            return [dict(r) for r in self.records]


def recover_engine(path: str | Path) -> AuditEngine:
    """Replay a local JSONL log into a fresh AuditEngine."""

    engine = AuditEngine()
    for record in _read_records(Path(path)):
        event = event_from_dict(record)
        engine.commit(event)
    return engine


def _read_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"corrupt commit log {path} line {line_number}: {exc}"
                ) from exc
            if record.get("seq") != len(records) + 1:
                raise RuntimeError(f"non-contiguous commit log at {path} line {line_number}")
            records.append(record)
    return records


class InjectedFault(RuntimeError):
    def __init__(self, phase: str, key: str, *, committed: bool, seq: int | None):
        super().__init__(
            f"injected {phase} fault for {key}; committed={committed}, seq={seq}"
        )
        self.phase = phase
        self.key = key
        self.committed = committed
        self.seq = seq


class FaultInjector:
    """One-shot local crash points keyed by aggregate/event identity."""

    def __init__(
        self,
        *,
        before_commit: set[str] | None = None,
        after_commit: set[str] | None = None,
    ) -> None:
        self.before_commit_keys = set(before_commit or ())
        self.after_commit_keys = set(after_commit or ())
        self.lock = threading.Lock()
        self.events: list[str] = []

    def before_commit(self, event: AuditEvent) -> None:
        key = fault_key(event)
        with self.lock:
            self.events.append(f"before:{key}:seq={event.seq}")
            if key in self.before_commit_keys:
                self.before_commit_keys.remove(key)
                raise InjectedFault("before_commit", key, committed=False, seq=None)

    def after_commit(self, event: AuditEvent) -> None:
        key = fault_key(event)
        with self.lock:
            self.events.append(f"after:{key}:seq={event.seq}")
            if key in self.after_commit_keys:
                self.after_commit_keys.remove(key)
                raise InjectedFault(
                    "after_commit", key, committed=True, seq=event.seq
                )


def fault_key(event: AuditEvent) -> str:
    if isinstance(event, GenerationAdvanced):
        return f"{event.evidence_id}#g{event.generation}"
    for attr in ("signoff_id", "grant_id", "root_id", "evidence_id"):
        value = getattr(event, attr, None)
        if value is not None:
            return str(value)
    return event.kind
