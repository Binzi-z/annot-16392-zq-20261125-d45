"""Fifty-thousand proxy-path incremental revocation check.

The incremental index maps a revoked grant to paths and therefore cases.  Only
the affected case shards are recomputed; afterward every path and every case
result is compared item-by-item with an independent full recomputation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PATH_COUNT = 50_000
CASE_COUNT = 100
PATHS_PER_CASE = PATH_COUNT // CASE_COUNT  # 500
DESIGNATED_REVOKED_GRANT = "HUB-C-025-1"


@dataclass(frozen=True)
class ProxyPath:
    path_id: int
    case_id: str
    evidence_id: str
    generation: int
    signoff_id: str
    reviewer_id: str
    cost: int
    root_id: str
    controller_id: str
    grant_ids: tuple[str, ...]


@dataclass(frozen=True)
class PathResult:
    path_id: int
    case_id: str
    valid: bool
    root_id: str
    controller_id: str
    reason: str | None
    revoked_grant: str | None


@dataclass(frozen=True)
class CaseProof:
    case_id: str
    releasable: bool
    total_cost: int | None
    path_ids: tuple[int, ...]
    signoff_ids: tuple[str, ...]
    reviewers: tuple[str, ...]
    root_ids: tuple[str, ...]
    controller_ids: tuple[str, ...]
    reason: str | None


def generate_paths(count: int = PATH_COUNT) -> list[ProxyPath]:
    if count != PATH_COUNT:
        raise ValueError("the scale check is fixed at 50,000 paths")
    paths: list[ProxyPath] = []
    for path_id in range(count):
        case_index = path_id // PATHS_PER_CASE
        within_case = path_id % PATHS_PER_CASE
        root_index = within_case % 4
        case_id = f"C-{case_index:03d}"
        root_id = f"ROOT-{case_id}-{root_index}"
        controller_id = f"ctl-{case_id}-{root_index}"
        hub_grant = f"HUB-{case_id}-{root_index}"
        spoke_grant = f"SPOKE-{path_id:05d}"
        paths.append(
            ProxyPath(
                path_id=path_id,
                case_id=case_id,
                evidence_id="EV-SHARED-SCALE",
                generation=1,
                signoff_id=f"SIG-{path_id:05d}",
                reviewer_id=f"reviewer-{case_id}-{within_case:03d}",
                # Deterministic costs in 1..9 without random-state dependence.
                cost=1 + (path_id * 7) % 9,
                root_id=root_id,
                controller_id=controller_id,
                grant_ids=(hub_grant, spoke_grant),
            )
        )
    return paths


def audit_path(path: ProxyPath, revoked: set[str]) -> PathResult:
    if path.root_id in revoked:
        return PathResult(
            path.path_id,
            path.case_id,
            False,
            path.root_id,
            path.controller_id,
            "ROOT_REVOKED",
            path.root_id,
        )
    for grant_id in path.grant_ids:
        if grant_id in revoked:
            return PathResult(
                path.path_id,
                path.case_id,
                False,
                path.root_id,
                path.controller_id,
                "GRANT_REVOKED",
                grant_id,
            )
    return PathResult(
        path.path_id,
        path.case_id,
        True,
        path.root_id,
        path.controller_id,
        None,
        None,
    )


def build_case_proof(
    case_id: str,
    paths: list[ProxyPath],
    results_by_id: dict[int, PathResult],
) -> CaseProof:
    """Choose the cheapest valid path for each root, then pair distinct roots."""

    case_paths = [p for p in paths if p.case_id == case_id]
    cheapest_by_root: dict[str, tuple[ProxyPath, PathResult]] = {}

    for path in case_paths:
        result = results_by_id[path.path_id]
        if not result.valid:
            continue
        current = cheapest_by_root.get(path.root_id)
        if current is None or (path.cost, path.path_id) < (
            current[0].cost,
            current[0].path_id,
        ):
            cheapest_by_root[path.root_id] = (path, result)

    root_choices = sorted(
        cheapest_by_root.values(),
        key=lambda item: (item[0].cost, item[0].path_id),
    )
    best_pair: tuple[ProxyPath, ProxyPath] | None = None
    best_key: tuple[Any, ...] | None = None

    for left_index in range(len(root_choices)):
        left = root_choices[left_index][0]
        for right_index in range(left_index + 1, len(root_choices)):
            right = root_choices[right_index][0]
            if left.root_id == right.root_id:
                continue
            if left.controller_id == right.controller_id:
                continue
            ordered = tuple(sorted((left, right), key=lambda p: p.path_id))
            key = (
                left.cost + right.cost,
                ordered[0].path_id,
                ordered[1].path_id,
            )
            if best_key is None or key < best_key:
                best_key = key
                best_pair = (ordered[0], ordered[1])

    if best_pair is None:
        return CaseProof(
            case_id,
            False,
            None,
            (),
            (),
            (),
            (),
            (),
            "NO_INDEPENDENT_PAIR",
        )

    left, right = best_pair
    return CaseProof(
        case_id=case_id,
        releasable=True,
        total_cost=left.cost + right.cost,
        path_ids=(left.path_id, right.path_id),
        signoff_ids=(left.signoff_id, right.signoff_id),
        reviewers=(left.reviewer_id, right.reviewer_id),
        root_ids=(left.root_id, right.root_id),
        controller_ids=(left.controller_id, right.controller_id),
        reason=None,
    )


def full_recompute(
    paths: list[ProxyPath], revoked: set[str]
) -> tuple[list[PathResult], dict[str, CaseProof]]:
    path_results = [audit_path(path, revoked) for path in paths]
    results_by_id = {result.path_id: result for result in path_results}
    case_ids = sorted({path.case_id for path in paths})
    case_results = {
        case_id: build_case_proof(case_id, paths, results_by_id)
        for case_id in case_ids
    }
    return path_results, case_results


class IncrementalScaleAuditor:
    def __init__(self, paths: list[ProxyPath]) -> None:
        self.paths = paths
        self.revoked: set[str] = set()
        self.grant_index: dict[str, list[int]] = {}
        self.case_index: dict[str, list[int]] = {}
        for path in paths:
            self.case_index.setdefault(path.case_id, []).append(path.path_id)
            for grant_id in (path.root_id, *path.grant_ids):
                self.grant_index.setdefault(grant_id, []).append(path.path_id)

        self.path_results: dict[int, PathResult] = {}
        self.case_results: dict[str, CaseProof] = {}
        self.recomputed_case_operations: list[list[str]] = []
        self.total_recomputed_paths = 0
        self._compute_all()

    def _compute_all(self) -> None:
        for path in self.paths:
            self.path_results[path.path_id] = audit_path(path, self.revoked)
        for case_id in sorted(self.case_index):
            self.case_results[case_id] = build_case_proof(
                case_id, self.paths, self.path_results
            )

    def revoke(self, grant_id: str) -> dict[str, Any]:
        self.revoked.add(grant_id)
        affected_ids = list(self.grant_index.get(grant_id, ()))
        relevant_cases = sorted(
            {self.paths[path_id].case_id for path_id in affected_ids}
        )

        recomputed_paths = 0
        for case_id in relevant_cases:
            for path_id in self.case_index[case_id]:
                path = self.paths[path_id]
                self.path_results[path_id] = audit_path(path, self.revoked)
                recomputed_paths += 1
            self.case_results[case_id] = build_case_proof(
                case_id, self.paths, self.path_results
            )

        self.recomputed_case_operations.append(relevant_cases)
        self.total_recomputed_paths += recomputed_paths
        return {
            "revoked_grant": grant_id,
            "affected_path_count": len(affected_ids),
            "affected_path_ids_sample": affected_ids[:5],
            "relevant_cases": relevant_cases,
            "recomputed_case_count": len(relevant_cases),
            "recomputed_path_count": recomputed_paths,
        }


def verify_scale() -> dict[str, Any]:
    paths = generate_paths()
    auditor = IncrementalScaleAuditor(paths)

    before_proof = auditor.case_results["C-025"]
    revocation_stats = auditor.revoke(DESIGNATED_REVOKED_GRANT)
    after_proof = auditor.case_results["C-025"]

    full_path_results, full_case_results = full_recompute(paths, auditor.revoked)

    path_mismatches: list[dict[str, Any]] = []
    for full_result in full_path_results:
        incremental_result = auditor.path_results[full_result.path_id]
        if incremental_result != full_result:
            if len(path_mismatches) < 10:
                path_mismatches.append(
                    {
                        "path_id": full_result.path_id,
                        "full": full_result.__dict__,
                        "incremental": incremental_result.__dict__,
                    }
                )

    case_mismatches: list[dict[str, Any]] = []
    for case_id, full_proof in full_case_results.items():
        incremental_proof = auditor.case_results[case_id]
        if incremental_proof != full_proof:
            if len(case_mismatches) < 10:
                case_mismatches.append(
                    {
                        "case_id": case_id,
                        "full": full_proof.__dict__,
                        "incremental": incremental_proof.__dict__,
                    }
                )

    expected_relevant_cases = ["C-025"]
    ok = (
        len(paths) == PATH_COUNT
        and len(full_path_results) == PATH_COUNT
        and len(full_case_results) == CASE_COUNT
        and revocation_stats["relevant_cases"] == expected_relevant_cases
        and revocation_stats["affected_path_count"] == 125
        and revocation_stats["recomputed_path_count"] == PATHS_PER_CASE
        and not path_mismatches
        and not case_mismatches
        and after_proof.releasable is True
    )

    return {
        "ok": ok,
        "path_count": len(paths),
        "case_count": len(full_case_results),
        "designated_revocation": DESIGNATED_REVOKED_GRANT,
        "revocation": revocation_stats,
        "before_proof_C025": before_proof.__dict__,
        "after_proof_C025": after_proof.__dict__,
        "path_item_comparison": {
            "compared_items": PATH_COUNT,
            "mismatch_count": len(path_mismatches),
            "mismatches": path_mismatches,
        },
        "case_item_comparison": {
            "compared_items": len(full_case_results),
            "mismatch_count": len(case_mismatches),
            "mismatches": case_mismatches,
        },
    }
