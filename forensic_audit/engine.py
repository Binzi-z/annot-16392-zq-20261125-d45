"""Deterministic watermark audit engine.

The engine is intentionally replay based: the committed event log is the only
source of truth.  A watermark is an event sequence number, so a decision at an
old watermark remains stable after later revocations or evidence rotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, ClassVar, Iterable


class ReasonCode(str, Enum):
    EVIDENCE_UNKNOWN = "EVIDENCE_UNKNOWN"
    EVIDENCE_NOT_IN_CASE = "EVIDENCE_NOT_IN_CASE"
    NO_SIGNOFF = "NO_SIGNOFF"
    STALE_GENERATION = "STALE_GENERATION"
    NO_ROOT_FOR_CASE = "NO_ROOT_FOR_CASE"
    ROOT_REVOKED = "ROOT_REVOKED"
    NO_ACTIVE_CHAIN = "NO_ACTIVE_CHAIN"
    GRANT_REVOKED = "GRANT_REVOKED"
    GRANT_CASE_MISMATCH = "GRANT_CASE_MISMATCH"
    DELEGATION_CYCLE = "DELEGATION_CYCLE"
    INSUFFICIENT_SEATS = "INSUFFICIENT_SEATS"
    SHARED_ROOT = "SHARED_ROOT"
    SAME_CONTROLLER = "SAME_CONTROLLER"
    SAME_REVIEWER = "SAME_REVIEWER"
    SAME_SIGNOFF = "SAME_SIGNOFF"
    NO_INDEPENDENT_PAIR = "NO_INDEPENDENT_PAIR"
    PREEMPTED_BY_REVOCATION = "PREEMPTED_BY_REVOCATION"
    PREEMPTED_BY_GENERATION = "PREEMPTED_BY_GENERATION"
    FAULT_BEFORE_COMMIT = "FAULT_BEFORE_COMMIT"
    FAULT_AFTER_COMMIT = "FAULT_AFTER_COMMIT"


# ---------------------------------------------------------------------------
# Committed events
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceRegistered:
    evidence_id: str
    case_ids: tuple[str, ...]
    initial_generation: int = 1
    seq: int = -1
    kind: ClassVar[str] = "evidence_registered"


@dataclass(frozen=True)
class GenerationAdvanced:
    evidence_id: str
    generation: int
    seq: int = -1
    kind: ClassVar[str] = "generation_advanced"


@dataclass(frozen=True)
class RootAuthorized:
    root_id: str
    controller_id: str
    case_id: str
    seq: int = -1
    kind: ClassVar[str] = "root_authorized"


@dataclass(frozen=True)
class DelegationGranted:
    grant_id: str
    root_id: str
    case_id: str
    delegator_id: str
    delegatee_id: str
    cost: int = 0
    seq: int = -1
    kind: ClassVar[str] = "delegation_granted"


@dataclass(frozen=True)
class GrantRevoked:
    grant_id: str
    seq: int = -1
    kind: ClassVar[str] = "grant_revoked"


@dataclass(frozen=True)
class SignoffCommitted:
    signoff_id: str
    case_id: str
    evidence_id: str
    generation: int
    reviewer_id: str
    cost: int = 1
    seq: int = -1
    kind: ClassVar[str] = "signoff_committed"


@dataclass(frozen=True)
class SignoffRejected:
    signoff_id: str
    case_id: str
    evidence_id: str
    attempted_generation: int
    reviewer_id: str
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)
    seq: int = -1
    kind: ClassVar[str] = "signoff_rejected"


AuditEvent = (
    EvidenceRegistered
    | GenerationAdvanced
    | RootAuthorized
    | DelegationGranted
    | GrantRevoked
    | SignoffCommitted
    | SignoffRejected
)


# ---------------------------------------------------------------------------
# Replay state and proof values
# ---------------------------------------------------------------------------


@dataclass
class _Evidence:
    cases: set[str]
    generation: int


@dataclass
class _Root:
    root_id: str
    controller_id: str
    case_id: str


@dataclass
class _Grant:
    grant_id: str
    root_id: str
    case_id: str
    delegator_id: str
    delegatee_id: str
    cost: int


@dataclass
class _Signoff:
    signoff_id: str
    case_id: str
    evidence_id: str
    generation: int
    reviewer_id: str
    cost: int
    seq: int


@dataclass
class ReplayState:
    evidence: dict[str, _Evidence] = field(default_factory=dict)
    roots: dict[str, _Root] = field(default_factory=dict)
    grants: dict[str, _Grant] = field(default_factory=dict)
    signoffs: dict[str, _Signoff] = field(default_factory=dict)
    revocations: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class BlockReason:
    code: str
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_jsonable(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "detail": self.detail}


@dataclass(frozen=True)
class Seat:
    signoff_id: str
    reviewer_id: str
    signoff_cost: int
    chain_cost: int
    total_cost: int
    root_id: str
    controller_id: str
    chain_grant_ids: tuple[str, ...]
    hops: tuple[tuple[str, str, str], ...]
    generation: int
    case_id: str

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "signoff_id": self.signoff_id,
            "reviewer_id": self.reviewer_id,
            "signoff_cost": self.signoff_cost,
            "chain_cost": self.chain_cost,
            "total_cost": self.total_cost,
            "root_authorization_id": self.root_id,
            "underlying_controller": self.controller_id,
            "chain_grant_ids": list(self.chain_grant_ids),
            "hops": [
                {"grant_id": g, "delegator": a, "delegatee": b}
                for g, a, b in self.hops
            ],
            "generation": self.generation,
            "case_id": self.case_id,
        }


@dataclass(frozen=True)
class Proof:
    seats: tuple[Seat, Seat]
    total_cost: int
    total_hops: int
    selection_key: tuple[Any, ...]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "seat_count": 2,
            "total_cost": self.total_cost,
            "total_delegation_hops": self.total_hops,
            "independence": {
                "distinct_underlying_controllers": sorted(
                    {s.controller_id for s in self.seats}
                ),
                "distinct_root_authorizations": sorted({s.root_id for s in self.seats}),
            },
            "seats": [s.to_jsonable() for s in self.seats],
        }


@dataclass(frozen=True)
class Decision:
    watermark: int
    case_id: str
    evidence_id: str
    current_generation: int | None
    releasable: bool
    proof: Proof | None
    reasons: tuple[BlockReason, ...]
    diagnostics: dict[str, Any]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "watermark": self.watermark,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "current_generation": self.current_generation,
            "releasable": self.releasable,
            "minimum_proof": self.proof.to_jsonable() if self.proof else None,
            "reasons": [r.to_jsonable() for r in self.reasons],
            "diagnostics": self.diagnostics,
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AuditEngine:
    """Append-only event log plus deterministic audit queries."""

    def __init__(self, events: Iterable[AuditEvent] = ()) -> None:
        self.events: list[AuditEvent] = []
        for event in events:
            self.commit(event)

    # -- write side ---------------------------------------------------------

    def commit(self, event: AuditEvent) -> int:
        seq = len(self.events) + 1
        committed = replace(event, seq=seq)  # type: ignore[arg-type]
        self.events.append(committed)
        return seq

    # Convenience builders keep scenario code readable.
    def register_evidence(
        self, evidence_id: str, case_ids: tuple[str, ...], generation: int = 1
    ) -> int:
        return self.commit(EvidenceRegistered(evidence_id, tuple(case_ids), generation))

    def advance_generation(self, evidence_id: str, generation: int) -> int:
        return self.commit(GenerationAdvanced(evidence_id, generation))

    def authorize_root(self, root_id: str, controller_id: str, case_id: str) -> int:
        return self.commit(RootAuthorized(root_id, controller_id, case_id))

    def grant(
        self,
        grant_id: str,
        root_id: str,
        case_id: str,
        delegator_id: str,
        delegatee_id: str,
        cost: int = 0,
    ) -> int:
        return self.commit(
            DelegationGranted(
                grant_id, root_id, case_id, delegator_id, delegatee_id, cost
            )
        )

    def revoke(self, grant_or_root_id: str) -> int:
        return self.commit(GrantRevoked(grant_or_root_id))

    def signoff(
        self,
        signoff_id: str,
        case_id: str,
        evidence_id: str,
        generation: int,
        reviewer_id: str,
        cost: int = 1,
    ) -> int:
        return self.commit(
            SignoffCommitted(
                signoff_id, case_id, evidence_id, generation, reviewer_id, cost
            )
        )

    # -- replay -------------------------------------------------------------

    def state_at(self, watermark: int | None = None) -> ReplayState:
        if watermark is None:
            watermark = len(self.events)
        state = ReplayState()
        for event in self.events:
            if event.seq > watermark:
                break
            _apply(state, event)
        return state

    def evaluate(
        self,
        case_id: str,
        evidence_id: str,
        watermark: int | None = None,
    ) -> Decision:
        if watermark is None:
            watermark = len(self.events)
        state = self.state_at(watermark)
        return _evaluate_state(state, watermark, case_id, evidence_id)

    def report_watermarks(
        self, extra_targets: Iterable[tuple[str, str]] = ()
    ) -> list[dict[str, Any]]:
        """Evaluate every known case/evidence target at every event watermark."""

        extras = tuple(extra_targets)
        state = ReplayState()
        report: list[dict[str, Any]] = []

        # Watermark zero is useful for tests and for an empty-log baseline.
        baseline_targets = sorted(set(extras))
        report.append(
            {
                "watermark": 0,
                "event": None,
                "decisions": [
                    _evaluate_state(state, 0, case_id, evidence_id).to_jsonable()
                    for case_id, evidence_id in baseline_targets
                ],
            }
        )

        for event in self.events:
            _apply(state, event)
            targets = set(extras)
            for evidence_id, item in state.evidence.items():
                for case_id in item.cases:
                    targets.add((case_id, evidence_id))
            decisions = [
                _evaluate_state(state, event.seq, case_id, evidence_id).to_jsonable()
                for case_id, evidence_id in sorted(targets)
            ]
            report.append(
                {
                    "watermark": event.seq,
                    "event": _event_summary(event),
                    "decisions": decisions,
                }
            )
        return report

    def minimum_proof(
        self, case_id: str, evidence_id: str, watermark: int | None = None
    ) -> Proof | None:
        return self.evaluate(case_id, evidence_id, watermark).proof


def _apply(state: ReplayState, event: AuditEvent) -> None:
    if isinstance(event, EvidenceRegistered):
        state.evidence[event.evidence_id] = _Evidence(
            cases=set(event.case_ids), generation=event.initial_generation
        )
    elif isinstance(event, GenerationAdvanced):
        evidence = state.evidence.get(event.evidence_id)
        if evidence is not None:
            evidence.generation = event.generation
    elif isinstance(event, RootAuthorized):
        state.roots[event.root_id] = _Root(
            event.root_id, event.controller_id, event.case_id
        )
    elif isinstance(event, DelegationGranted):
        state.grants[event.grant_id] = _Grant(
            event.grant_id,
            event.root_id,
            event.case_id,
            event.delegator_id,
            event.delegatee_id,
            event.cost,
        )
    elif isinstance(event, GrantRevoked):
        state.revocations[event.grant_id] = event.seq
    elif isinstance(event, SignoffCommitted):
        state.signoffs[event.signoff_id] = _Signoff(
            event.signoff_id,
            event.case_id,
            event.evidence_id,
            event.generation,
            event.reviewer_id,
            event.cost,
            event.seq,
        )
    elif isinstance(event, SignoffRejected):
        # A rejection is an audit record only; it never becomes a seat.
        return


def _event_summary(event: AuditEvent) -> dict[str, Any]:
    data: dict[str, Any] = {"seq": event.seq, "kind": event.kind}
    for key in (
        "evidence_id",
        "case_id",
        "generation",
        "root_id",
        "controller_id",
        "grant_id",
        "signoff_id",
        "reviewer_id",
        "reason",
    ):
        if hasattr(event, key):
            value = getattr(event, key)
            if value is not None:
                data[key] = value
    return data


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _evaluate_state(
    state: ReplayState, watermark: int, case_id: str, evidence_id: str
) -> Decision:
    diagnostics: dict[str, Any] = {}
    evidence = state.evidence.get(evidence_id)

    if evidence is None:
        reason = BlockReason(
            ReasonCode.EVIDENCE_UNKNOWN.value,
            "Evidence is not present in the committed warehouse log.",
            {"evidence_id": evidence_id},
        )
        return Decision(
            watermark, case_id, evidence_id, None, False, None, (reason,), diagnostics
        )

    current_generation = evidence.generation
    diagnostics["evidence_cases"] = sorted(evidence.cases)

    if case_id not in evidence.cases:
        reason = BlockReason(
            ReasonCode.EVIDENCE_NOT_IN_CASE.value,
            "Case isolation: evidence is not registered to this case.",
            {
                "requested_case": case_id,
                "registered_cases": sorted(evidence.cases),
            },
        )
        return Decision(
            watermark,
            case_id,
            evidence_id,
            current_generation,
            False,
            None,
            (reason,),
            diagnostics,
        )

    case_signoffs = [
        s
        for s in state.signoffs.values()
        if s.evidence_id == evidence_id and s.case_id == case_id
    ]
    cross_case_signoffs = [
        s.signoff_id
        for s in state.signoffs.values()
        if s.evidence_id == evidence_id and s.case_id != case_id
    ]
    diagnostics["cross_case_signoffs_ignored"] = sorted(cross_case_signoffs)

    matching = [s for s in case_signoffs if s.generation == current_generation]
    stale = [
        {
            "signoff_id": s.signoff_id,
            "signed_generation": s.generation,
            "committed_seq": s.seq,
        }
        for s in case_signoffs
        if s.generation != current_generation
    ]
    diagnostics["stale_signoffs"] = stale

    if not matching:
        if stale:
            reason = BlockReason(
                ReasonCode.STALE_GENERATION.value,
                "All sign-offs target an older or newer evidence generation.",
                {
                    "current_generation": current_generation,
                    "stale": stale,
                },
            )
        else:
            reason = BlockReason(
                ReasonCode.NO_SIGNOFF.value,
                "No committed sign-off exists for this case, evidence and generation.",
                {
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "generation": current_generation,
                },
            )
        return Decision(
            watermark,
            case_id,
            evidence_id,
            current_generation,
            False,
            None,
            (reason,),
            diagnostics,
        )

    case_roots = [r for r in state.roots.values() if r.case_id == case_id]
    active_roots = [r for r in case_roots if r.root_id not in state.revocations]
    diagnostics.update(
        {
            "matching_signoff_ids": sorted(s.signoff_id for s in matching),
            "roots_for_case": sorted(r.root_id for r in case_roots),
            "active_roots_for_case": sorted(r.root_id for r in active_roots),
        }
    )

    reasons: list[BlockReason] = []
    if not case_roots:
        reasons.append(
            BlockReason(
                ReasonCode.NO_ROOT_FOR_CASE.value,
                "No underlying controller authorization exists for this case.",
                {"case_id": case_id},
            )
        )
    elif not active_roots:
        reasons.append(
            BlockReason(
                ReasonCode.ROOT_REVOKED.value,
                "Every root authorization for this case has been revoked.",
                {"revoked_roots": sorted(r.root_id for r in case_roots)},
            )
        )

    seats: list[Seat] = []
    chain_blockers: list[dict[str, Any]] = []
    for signoff in sorted(matching, key=lambda s: s.signoff_id):
        signoff_seats: list[Seat] = []
        for root in active_roots:
            chains, blockers = _resolve_chains(state, root, signoff.reviewer_id)
            chain_blockers.extend(blockers)
            if chains:
                best_chain = min(
                    chains,
                    key=lambda c: (
                        c["cost"],
                        len(c["grant_ids"]),
                        c["grant_ids"],
                    ),
                )
                seat = Seat(
                    signoff_id=signoff.signoff_id,
                    reviewer_id=signoff.reviewer_id,
                    signoff_cost=signoff.cost,
                    chain_cost=best_chain["cost"],
                    total_cost=signoff.cost + best_chain["cost"],
                    root_id=root.root_id,
                    controller_id=root.controller_id,
                    chain_grant_ids=tuple(best_chain["grant_ids"]),
                    hops=tuple(
                        (g["grant_id"], g["delegator"], g["delegatee"])
                        for g in best_chain["hops"]
                    ),
                    generation=signoff.generation,
                    case_id=signoff.case_id,
                )
                signoff_seats.append(seat)
        # For one signoff/root, _resolve_chains already returns all routes; the
        # minimum route was selected above.  Different roots remain different
        # possible seats.
        seats.extend(signoff_seats)

    diagnostics["seat_candidates"] = [
        {
            "signoff_id": s.signoff_id,
            "reviewer_id": s.reviewer_id,
            "root_id": s.root_id,
            "controller_id": s.controller_id,
            "total_cost": s.total_cost,
        }
        for s in sorted(seats, key=lambda s: (s.signoff_id, s.root_id))
    ]

    proof, pair_blockers = _minimum_independent_pair(seats)

    if proof is not None:
        return Decision(
            watermark,
            case_id,
            evidence_id,
            current_generation,
            True,
            proof,
            (),
            diagnostics,
        )

    if len({s.signoff_id for s in seats}) < 2 or len(matching) < 2:
        reasons.append(
            BlockReason(
                ReasonCode.INSUFFICIENT_SEATS.value,
                "Fewer than two distinct committed sign-offs can reach active roots.",
                {
                    "matching_signoff_count": len(matching),
                    "usable_signoff_ids": sorted({s.signoff_id for s in seats}),
                },
            )
        )
    if not seats and chain_blockers:
        # De-duplicate identical blockers before exposing them.
        unique_blockers = sorted(
            {
                (b["code"], b.get("grant_id", ""), b.get("root_id", "")): b
                for b in chain_blockers
            }.values(),
            key=lambda b: (b["code"], b.get("grant_id", ""), b.get("root_id", "")),
        )
        reasons.append(
            BlockReason(
                ReasonCode.NO_ACTIVE_CHAIN.value,
                "At least one sign-off exists, but no active delegation chain "
                "connects it to an authorized underlying controller.",
                {"chain_blockers": unique_blockers[:20]},
            )
        )
    if seats:
        counts = {
            ReasonCode.SHARED_ROOT.value: pair_blockers.count(
                ReasonCode.SHARED_ROOT.value
            ),
            ReasonCode.SAME_CONTROLLER.value: pair_blockers.count(
                ReasonCode.SAME_CONTROLLER.value
            ),
            ReasonCode.SAME_REVIEWER.value: pair_blockers.count(
                ReasonCode.SAME_REVIEWER.value
            ),
            ReasonCode.SAME_SIGNOFF.value: pair_blockers.count(
                ReasonCode.SAME_SIGNOFF.value
            ),
        }
        reasons.append(
            BlockReason(
                ReasonCode.NO_INDEPENDENT_PAIR.value,
                "Two seats exist, but no pair comes from distinct sign-offs, "
                "reviewers, root authorizations and underlying controllers.",
                {"rejected_pair_count": len(pair_blockers), "conflicts": counts},
            )
        )

    if not reasons:
        reasons.append(
            BlockReason(
                "NOT_RELEASABLE",
                "No minimum independent proof was found.",
                {"seat_count": len(seats)},
            )
        )

    return Decision(
        watermark,
        case_id,
        evidence_id,
        current_generation,
        False,
        None,
        tuple(reasons),
        diagnostics,
    )


def _resolve_chains(
    state: ReplayState, root: _Root, reviewer_id: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate simple delegation paths from a root controller to reviewer."""

    adjacency: dict[str, list[_Grant]] = {}
    for grant in state.grants.values():
        if grant.root_id == root.root_id:
            adjacency.setdefault(grant.delegator_id, []).append(grant)
    for grants in adjacency.values():
        grants.sort(key=lambda g: (g.delegator_id, g.delegatee_id, g.grant_id))

    valid: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    path_limit = 64

    def visit(
        node: str,
        grant_path: list[_Grant],
        visited_nodes: set[str],
    ) -> None:
        if len(valid) + len(blockers) >= path_limit:
            return
        if node == reviewer_id:
            if not grant_path:
                # The underlying controller's own sign-off is a zero-hop seat.
                valid.append(
                    {"grant_ids": (), "hops": (), "cost": 0}
                )
                return
            bad: BlockReason | None = None
            blocker_detail: dict[str, Any] | None = None
            for grant in grant_path:
                if grant.case_id != root.case_id or grant.case_id != state.roots[
                    root.root_id
                ].case_id:
                    bad = ReasonCode.GRANT_CASE_MISMATCH
                    blocker_detail = {
                        "root_id": root.root_id,
                        "grant_id": grant.grant_id,
                        "expected_case": root.case_id,
                        "actual_case": grant.case_id,
                    }
                    break
                if grant.grant_id in state.revocations:
                    bad = ReasonCode.GRANT_REVOKED
                    blocker_detail = {
                        "root_id": root.root_id,
                        "grant_id": grant.grant_id,
                        "revoked_at_watermark": state.revocations[grant.grant_id],
                    }
                    break
            if bad is not None and blocker_detail is not None:
                blockers.append({"code": bad.value, **blocker_detail})
            else:
                valid.append(
                    {
                        "grant_ids": tuple(g.grant_id for g in grant_path),
                        "hops": tuple(
                            {
                                "grant_id": g.grant_id,
                                "delegator": g.delegator_id,
                                "delegatee": g.delegatee_id,
                            }
                            for g in grant_path
                        ),
                        "cost": sum(g.cost for g in grant_path),
                    }
                )
            return

        for grant in adjacency.get(node, ()):  # deterministic sorted above
            if grant.delegatee_id in visited_nodes:
                blockers.append(
                    {
                        "code": ReasonCode.DELEGATION_CYCLE.value,
                        "root_id": root.root_id,
                        "grant_id": grant.grant_id,
                        "node": grant.delegatee_id,
                    }
                )
                continue
            visited_nodes.add(grant.delegatee_id)
            grant_path.append(grant)
            visit(grant.delegatee_id, grant_path, visited_nodes)
            grant_path.pop()
            visited_nodes.remove(grant.delegatee_id)

    visit(root.controller_id, [], {root.controller_id})
    return valid, blockers


def _minimum_independent_pair(
    seats: list[Seat],
) -> tuple[Proof | None, list[str]]:
    conflict_codes: list[str] = []
    best: Proof | None = None

    for i, left in enumerate(seats):
        for right in seats[i + 1 :]:
            code = _independence_conflict(left, right)
            if code is not None:
                conflict_codes.append(code)
                continue

            ordered = tuple(sorted((left, right), key=lambda s: s.signoff_id))
            total_cost = left.total_cost + right.total_cost
            total_hops = len(left.chain_grant_ids) + len(right.chain_grant_ids)
            selection_key = (
                total_cost,
                total_hops,
                tuple(s.signoff_id for s in ordered),  # type: ignore[arg-type]
                tuple(s.root_id for s in ordered),  # type: ignore[arg-type]
            )
            proof = Proof(
                seats=ordered,  # type: ignore[arg-type]
                total_cost=total_cost,
                total_hops=total_hops,
                selection_key=selection_key,
            )
            if best is None or selection_key < best.selection_key:
                best = proof

    return best, conflict_codes


def _independence_conflict(left: Seat, right: Seat) -> str | None:
    if left.signoff_id == right.signoff_id:
        return ReasonCode.SAME_SIGNOFF.value
    if left.reviewer_id == right.reviewer_id:
        return ReasonCode.SAME_REVIEWER.value
    if left.root_id == right.root_id:
        return ReasonCode.SHARED_ROOT.value
    if left.controller_id == right.controller_id:
        return ReasonCode.SAME_CONTROLLER.value
    return None


# ---------------------------------------------------------------------------
# Shared synthetic scenario
# ---------------------------------------------------------------------------


def build_demo_engine() -> AuditEngine:
    """Build the small scenario used by the CLI and unit tests."""

    engine = AuditEngine()

    # Shared evidence makes the case-isolation failure visible.
    engine.register_evidence("EV-SHARED", ("CASE-ALPHA", "CASE-BETA"), generation=1)
    engine.register_evidence("EV-ALPHA-ONLY", ("CASE-ALPHA",), generation=1)

    # Alpha has three underlying controllers.  Beta has none.
    engine.authorize_root("ROOT-MAYER", "ctl_mayer", "CASE-ALPHA")
    engine.authorize_root("ROOT-OKAFOR", "ctl_okafor", "CASE-ALPHA")
    engine.authorize_root("ROOT-PARK", "ctl_park", "CASE-ALPHA")

    # Multi-hop Mayer -> Dalton -> Reyes.
    engine.grant("G-MAYER-DALTON", "ROOT-MAYER", "CASE-ALPHA", "ctl_mayer", "dalton")
    engine.grant("G-DALTON-REYES", "ROOT-MAYER", "CASE-ALPHA", "dalton", "reyes")

    # Direct Okafor -> Ito.
    engine.grant("G-OKAFOR-ITO", "ROOT-OKAFOR", "CASE-ALPHA", "ctl_okafor", "ito")

    # One root fans out through Voss to two cheap reviewers.  Those two seats
    # must never count as two independent controllers.
    engine.grant("G-OKAFOR-VOSS", "ROOT-OKAFOR", "CASE-ALPHA", "ctl_okafor", "voss")
    engine.grant("G-VOSS-CHEN", "ROOT-OKAFOR", "CASE-ALPHA", "voss", "chen")
    engine.grant("G-VOSS-PATEL", "ROOT-OKAFOR", "CASE-ALPHA", "voss", "patel")

    # Park -> Sato gives a genuinely independent third root.
    engine.grant("G-PARK-SATO", "ROOT-PARK", "CASE-ALPHA", "ctl_park", "sato")

    # Watermarks 5-8: one seat, then an expensive valid pair.
    engine.signoff("SIG-REYES", "CASE-ALPHA", "EV-SHARED", 1, "reyes", cost=9)
    engine.signoff("SIG-ITO", "CASE-ALPHA", "EV-SHARED", 1, "ito", cost=5)

    # The cheap-looking but non-independent pair.
    engine.signoff("SIG-CHEN", "CASE-ALPHA", "EV-SHARED", 1, "chen", cost=1)
    engine.signoff("SIG-PATEL", "CASE-ALPHA", "EV-SHARED", 1, "patel", cost=1)

    # Independent cheap witness under Park.  Chen+Sato is the first minimum.
    engine.signoff("SIG-SATO", "CASE-ALPHA", "EV-SHARED", 1, "sato", cost=2)

    # A sign-off for Beta on the same evidence must not help Alpha, and Beta
    # still lacks a Beta root authorization.
    engine.signoff("SIG-BETA-CROSS", "CASE-BETA", "EV-SHARED", 1, "ito", cost=1)

    # Revoke the shared Okafor -> Voss hub.  Chen and Patel disappear together;
    # Ito's separate direct Okafor grant remains available.
    engine.revoke("G-OKAFOR-VOSS")

    # Evidence rotation makes every generation-1 approval stale.
    engine.advance_generation("EV-SHARED", 2)

    # New generation witnesses.
    engine.signoff("SIG-ITO-G2", "CASE-ALPHA", "EV-SHARED", 2, "ito", cost=1)
    engine.signoff("SIG-SATO-G2", "CASE-ALPHA", "EV-SHARED", 2, "sato", cost=2)

    return engine
