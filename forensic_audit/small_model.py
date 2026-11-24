"""Independent brute-force small model.

This module deliberately does not reuse the engine's pair minimizer.  It
enumerates reviewer pairs, root choices and every short interleaving, then the
optimized engine/service output is compared against that separate oracle.
"""

from __future__ import annotations

from itertools import combinations, permutations, product
from typing import Any

from .concurrency import SignoffRequest, new_race_service
from .engine import AuditEngine

_REVIEWERS = ("reviewer_0", "reviewer_1", "reviewer_2")
_ROOT_IDS = ("root_0", "root_1", "root_2")
_CONTROLLERS = ("controller_0", "controller_1", "controller_2")
_CASE = "CASE-SMALL"
_EVIDENCE = "EV-SMALL"


def _all_subsets(items: tuple[int, ...]) -> tuple[tuple[int, ...], ...]:
    subsets: list[tuple[int, ...]] = [()]
    for size in range(1, len(items) + 1):
        subsets.extend(combinations(items, size))
    return tuple(subsets)


def oracle_minimum(
    reachable_roots: tuple[tuple[int, ...], ...],
    costs: tuple[int, ...],
    revoked_roots: tuple[int, ...],
) -> dict[str, Any]:
    """Brute-force all reviewer combinations and independent root choices."""

    revoked = set(revoked_roots)
    active = [i for i in range(len(_ROOT_IDS)) if i not in revoked]
    optimal: set[tuple[Any, ...]] = set()
    minimum_cost: int | None = None

    # Enumerate all reviewer subsets explicitly; only size two can satisfy the
    # two-seat rule, but recording sizes makes the model self-documenting.
    for size in range(len(_REVIEWERS) + 1):
        for reviewer_indexes in combinations(range(len(_REVIEWERS)), size):
            if size != 2:
                continue
            i, j = reviewer_indexes
            for root_i in reachable_roots[i]:
                if root_i not in active:
                    continue
                for root_j in reachable_roots[j]:
                    if root_j not in active:
                        continue
                    if _ROOT_IDS[root_i] == _ROOT_IDS[root_j]:
                        continue
                    if _CONTROLLERS[root_i] == _CONTROLLERS[root_j]:
                        continue
                    cost = costs[i] + costs[j]
                    key = (
                        cost,
                        frozenset((_REVIEWERS[i], _REVIEWERS[j])),
                        frozenset((_ROOT_IDS[root_i], _ROOT_IDS[root_j])),
                    )
                    if minimum_cost is None or cost < minimum_cost:
                        minimum_cost = cost
                        optimal = {key}
                    elif cost == minimum_cost:
                        optimal.add(key)

    return {
        "releasable": minimum_cost is not None,
        "minimum_cost": minimum_cost,
        "optimal_proofs": sorted(
            (cost, sorted(reviewers), sorted(roots))
            for cost, reviewers, roots in optimal
        ),
    }


def _build_reviewer_engine(
    reachable_roots: tuple[tuple[int, ...], ...],
    costs: tuple[int, ...],
    revoked_roots: tuple[int, ...],
) -> AuditEngine:
    engine = AuditEngine()
    engine.register_evidence(_EVIDENCE, (_CASE,), 1)
    for idx, root_id in enumerate(_ROOT_IDS):
        engine.authorize_root(root_id, _CONTROLLERS[idx], _CASE)

    for reviewer_idx, root_indexes in enumerate(reachable_roots):
        reviewer = _REVIEWERS[reviewer_idx]
        for root_idx in root_indexes:
            engine.grant(
                f"grant-{reviewer_idx}-{root_idx}",
                _ROOT_IDS[root_idx],
                _CASE,
                _CONTROLLERS[root_idx],
                reviewer,
            )
        engine.signoff(
            f"signoff-{reviewer_idx}",
            _CASE,
            _EVIDENCE,
            1,
            reviewer,
            cost=costs[reviewer_idx],
        )

    for root_idx in revoked_roots:
        engine.revoke(_ROOT_IDS[root_idx])
    return engine


def verify_reviewer_combinations() -> dict[str, Any]:
    root_indexes = tuple(range(len(_ROOT_IDS)))
    subsets = _all_subsets(root_indexes)
    cost_profiles = (
        (1, 2, 4),
        (1, 1, 5),
        (3, 2, 1),
    )
    case_count = 0
    failures: list[dict[str, Any]] = []

    for reachable_roots in product(subsets, repeat=len(_REVIEWERS)):
        for revoked_roots in subsets:
            for costs in cost_profiles:
                case_count += 1
                oracle = oracle_minimum(reachable_roots, costs, revoked_roots)
                engine = _build_reviewer_engine(
                    reachable_roots, costs, revoked_roots
                )
                decision = engine.evaluate(_CASE, _EVIDENCE)

                if decision.releasable != oracle["releasable"]:
                    failures.append(
                        {
                            "kind": "releasable_mismatch",
                            "reachable_roots": reachable_roots,
                            "costs": costs,
                            "revoked_roots": revoked_roots,
                            "oracle": oracle,
                            "engine_reasons": [
                                r.to_jsonable() for r in decision.reasons
                            ],
                        }
                    )
                    continue

                if not oracle["releasable"]:
                    continue

                proof = decision.proof
                assert proof is not None
                reviewers = frozenset(s.reviewer_id for s in proof.seats)
                roots = frozenset(s.root_id for s in proof.seats)
                actual_key = (proof.total_cost, reviewers, roots)
                optimal_keys = {
                    (cost, frozenset(reviewers), frozenset(roots))
                    for cost, reviewers, roots in oracle["optimal_proofs"]
                }
                if proof.total_cost != oracle["minimum_cost"] or actual_key not in optimal_keys:
                    failures.append(
                        {
                            "kind": "minimum_proof_mismatch",
                            "reachable_roots": reachable_roots,
                            "costs": costs,
                            "revoked_roots": revoked_roots,
                            "actual_cost": proof.total_cost,
                            "actual_reviewers": sorted(reviewers),
                            "actual_roots": sorted(roots),
                            "oracle": oracle,
                        }
                    )
                    if len(failures) >= 10:
                        return {
                            "ok": False,
                            "case_count": case_count,
                            "failures": failures,
                        }

    return {"ok": not failures, "case_count": case_count, "failures": failures}


def all_short_interleavings() -> list[tuple[str, ...]]:
    """All 30 shuffles of two two-step threads plus a one-step revocation."""

    signoff_steps = ("S_validate", "S_commit")
    generation_steps = ("G_validate", "G_commit")
    revocation_steps = ("R_commit",)
    steps = signoff_steps + generation_steps + revocation_steps
    interleavings: list[tuple[str, ...]] = []
    for order in permutations(steps):
        if order.index("S_validate") > order.index("S_commit"):
            continue
        if order.index("G_validate") > order.index("G_commit"):
            continue
        interleavings.append(order)
    # permutations emits duplicates because the implementation labels are all
    # distinct here, but guard the expected count explicitly.
    unique = sorted(set(interleavings))
    if len(unique) != 30:
        raise AssertionError(f"expected 30 short interleavings, got {len(unique)}")
    return unique


def oracle_commit_outcome(commit_order: tuple[str, ...]) -> dict[str, Any]:
    generation = 1
    revoked = False
    signoff_status: str | None = None
    signoff_reason: str | None = None
    signoff_committed = False

    for step in commit_order:
        if step == "G_commit":
            generation = 2
        elif step == "R_commit":
            revoked = True
        elif step == "S_commit":
            if generation != 1:
                signoff_status = "preempted"
                signoff_reason = "PREEMPTED_BY_GENERATION"
            elif revoked:
                signoff_status = "preempted"
                signoff_reason = "PREEMPTED_BY_REVOCATION"
            else:
                signoff_status = "committed"
                signoff_committed = True

    historical_releasable: bool | None = None
    if signoff_committed:
        # At the sign-off commit point neither blocking event had happened.
        historical_releasable = True

    return {
        "status": signoff_status,
        "reason": signoff_reason,
        "historical_releasable": historical_releasable,
        "final_releasable": False,  # generation step is present in every order
    }


def verify_short_interleavings() -> dict[str, Any]:
    interleavings = all_short_interleavings()
    failures: list[dict[str, Any]] = []
    executed = 0

    for order in interleavings:
        executed += 1
        service, request = new_race_service()
        result = None
        validation_problems: list[str] = []

        for step in order:
            if step == "S_validate":
                with service.lock:
                    problem = service._signoff_problem_locked(request)
                if problem is not None:
                    validation_problems.append(problem[0])
            elif step == "G_validate":
                # Read-only existence check; validation never reserves state.
                with service.lock:
                    if "EV-RACE" not in service.engine.state_at().evidence:
                        validation_problems.append("EVIDENCE_UNKNOWN")
            elif step == "S_commit":
                result = service.submit_signoff(request)
            elif step == "G_commit":
                service.advance_generation("EV-RACE", 2)
            elif step == "R_commit":
                service.revoke("G-R1")

        commit_order = tuple(step for step in order if step.endswith("_commit"))
        oracle = oracle_commit_outcome(commit_order)
        actual_status = result.status if result is not None else None
        actual_reason = result.reason if result is not None else None

        ok = (
            actual_status == oracle["status"]
            and actual_reason == oracle["reason"]
        )
        historical = None
        if actual_status == "committed" and result is not None and result.seq:
            historical = service.engine.evaluate(
                request.case_id, request.evidence_id, result.seq
            ).releasable
            final = service.engine.evaluate(
                request.case_id, request.evidence_id
            ).releasable
            ok = ok and historical is True and final is False

        if not ok:
            failures.append(
                {
                    "interleaving": order,
                    "commit_order": commit_order,
                    "oracle": oracle,
                    "actual_status": actual_status,
                    "actual_reason": actual_reason,
                    "historical_releasable": historical,
                    "validation_problems": validation_problems,
                }
            )

    return {
        "ok": not failures,
        "interleaving_count": executed,
        "failures": failures,
    }


def verify_small_model() -> dict[str, Any]:
    reviewers = verify_reviewer_combinations()
    interleavings = verify_short_interleavings()
    return {
        "ok": reviewers["ok"] and interleavings["ok"],
        "reviewer_enumeration": reviewers,
        "interleaving_enumeration": interleavings,
    }
