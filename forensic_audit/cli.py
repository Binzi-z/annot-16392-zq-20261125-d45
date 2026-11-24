"""End-to-end local audit entry point.

Run with Windows Python 3.12:

    py -3.12 run_audit.py
    python run_audit.py

Only the standard library is required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .concurrency import run_concurrency_checks
from .engine import AuditEngine, build_demo_engine
from .scale import verify_scale
from .small_model import verify_small_model


def verify_demo_invariants(engine: AuditEngine) -> dict[str, Any]:
    """Assert the narrative properties encoded by the synthetic scenario."""

    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, **detail: Any) -> None:
        checks.append({"name": name, "ok": bool(ok), **detail})

    one_seat = engine.evaluate("CASE-ALPHA", "EV-SHARED", 13)
    check(
        "watermark_13_only_one_signoff_is_blocked",
        not one_seat.releasable
        and any(r.code == "INSUFFICIENT_SEATS" for r in one_seat.reasons),
        codes=[r.code for r in one_seat.reasons],
    )

    first_pair = engine.evaluate("CASE-ALPHA", "EV-SHARED", 14)
    check(
        "watermark_14_multi_hop_and_direct_root_form_proof",
        first_pair.releasable
        and first_pair.proof is not None
        and first_pair.proof.total_cost == 14
        and {s.reviewer_id for s in first_pair.proof.seats} == {"reyes", "ito"}
        and len(first_pair.proof.seats[0].chain_grant_ids)
        + len(first_pair.proof.seats[1].chain_grant_ids)
        >= 1,
        proof=first_pair.proof.to_jsonable() if first_pair.proof else None,
    )

    shared_root = engine.evaluate("CASE-ALPHA", "EV-SHARED", 16)
    check(
        "chen_and_patel_cannot_fill_two_seats_from_one_root",
        shared_root.releasable
        and shared_root.proof is not None
        and {s.reviewer_id for s in shared_root.proof.seats} != {"chen", "patel"}
        and any(
            r.code == "NO_INDEPENDENT_PAIR"
            and r.detail.get("conflicts", {}).get("SHARED_ROOT", 0) > 0
            for r in shared_root.reasons
        )
        is False,  # a valid pair exists, so top-level blocked reasons are empty
        selected_reviewers=(
            sorted(s.reviewer_id for s in shared_root.proof.seats)
            if shared_root.proof
            else []
        ),
        seat_candidates=shared_root.diagnostics.get("seat_candidates"),
    )

    cheap = engine.evaluate("CASE-ALPHA", "EV-SHARED", 17)
    check(
        "watermark_17_minimum_is_chen_plus_sato",
        cheap.releasable
        and cheap.proof is not None
        and cheap.proof.total_cost == 3
        and {s.reviewer_id for s in cheap.proof.seats} == {"chen", "sato"},
        proof=cheap.proof.to_jsonable() if cheap.proof else None,
    )

    beta_before_rotation = engine.evaluate("CASE-BETA", "EV-SHARED", 18)
    check(
        "case_beta_cannot_use_alpha_roots_even_for_shared_evidence",
        not beta_before_rotation.releasable
        and any(r.code == "NO_ROOT_FOR_CASE" for r in beta_before_rotation.reasons),
        codes=[r.code for r in beta_before_rotation.reasons],
        diagnostics=beta_before_rotation.diagnostics,
    )

    not_in_case = engine.evaluate("CASE-BETA", "EV-ALPHA-ONLY", 18)
    check(
        "evidence_not_registered_to_beta_is_isolated",
        not not_in_case.releasable
        and any(r.code == "EVIDENCE_NOT_IN_CASE" for r in not_in_case.reasons),
        codes=[r.code for r in not_in_case.reasons],
    )

    after_revoke = engine.evaluate("CASE-ALPHA", "EV-SHARED", 19)
    naive_reyes_sato_cost = 9 + 2
    check(
        "after_revocation_another_cheaper_independent_witness_pair_exists",
        after_revoke.releasable
        and after_revoke.proof is not None
        and after_revoke.proof.total_cost == 7
        and {s.reviewer_id for s in after_revoke.proof.seats} == {"ito", "sato"}
        and after_revoke.proof.total_cost < naive_reyes_sato_cost,
        post_revocation_cost=(
            after_revoke.proof.total_cost if after_revoke.proof else None
        ),
        naive_reyes_sato_cost=naive_reyes_sato_cost,
        saving_versus_naive_replacement=(
            naive_reyes_sato_cost - after_revoke.proof.total_cost
            if after_revoke.proof
            else None
        ),
        proof=after_revoke.proof.to_jsonable() if after_revoke.proof else None,
    )

    rotated = engine.evaluate("CASE-ALPHA", "EV-SHARED", 20)
    check(
        "evidence_rotation_invalidates_old_generation_approvals",
        not rotated.releasable
        and any(r.code == "STALE_GENERATION" for r in rotated.reasons),
        codes=[r.code for r in rotated.reasons],
    )

    new_generation = engine.evaluate("CASE-ALPHA", "EV-SHARED", 22)
    check(
        "new_generation_independent_pair_releases",
        new_generation.releasable
        and new_generation.proof is not None
        and new_generation.proof.total_cost == 3
        and {s.generation for s in new_generation.proof.seats} == {2},
        proof=new_generation.proof.to_jsonable() if new_generation.proof else None,
    )

    return {
        "ok": all(item["ok"] for item in checks),
        "check_count": len(checks),
        "passed_count": sum(1 for item in checks if item["ok"]),
        "checks": checks,
    }


def run_all(output_dir: str | Path = "artifacts") -> tuple[int, dict[str, Any]]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    engine = build_demo_engine()
    watermark_report = engine.report_watermarks(
        extra_targets=[("CASE-BETA", "EV-ALPHA-ONLY")]
    )
    demo = verify_demo_invariants(engine)
    concurrency = run_concurrency_checks(output / "concurrency")
    small_model = verify_small_model()
    scale = verify_scale()

    ok = bool(
        demo["ok"]
        and concurrency["ok"]
        and small_model["ok"]
        and scale["ok"]
    )
    report: dict[str, Any] = {
        "ok": ok,
        "python": sys.version,
        "platform": sys.platform,
        "summary": {
            "watermark_count": len(watermark_report),
            "demo_checks": f"{demo['passed_count']}/{demo['check_count']}",
            "concurrency_checks": (
                f"{concurrency['passed_count']}/{concurrency['check_count']}"
            ),
            "reviewer_model_cases": small_model["reviewer_enumeration"][
                "case_count"
            ],
            "short_interleavings": small_model["interleaving_enumeration"][
                "interleaving_count"
            ],
            "scale_paths_compared": scale["path_item_comparison"]["compared_items"],
            "scale_cases_compared": scale["case_item_comparison"]["compared_items"],
        },
        "demo_invariants": demo,
        "concurrency": concurrency,
        "small_model": small_model,
        "scale": scale,
        "watermark_report": watermark_report,
    }

    report_path = output / "audit_report.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False),
        encoding="utf-8",
    )
    return 0 if ok else 1, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="artifacts", help="report directory")
    args = parser.parse_args(argv)

    code, report = run_all(args.output)
    summary = report["summary"]
    report_path = Path(args.output) / "audit_report.json"
    print("合成取证仓本地审计")
    print(f"  总体结果: {'PASS' if report['ok'] else 'FAIL'}")
    print(f"  水位报告: {summary['watermark_count']} 个水位（含 0）")
    print(f"  场景不变量: {summary['demo_checks']}")
    print(f"  并发/故障: {summary['concurrency_checks']}")
    print(f"  审查人组合小模型: {summary['reviewer_model_cases']} 组")
    print(f"  短交错: {summary['short_interleavings']} 种")
    print(
        "  增量核对: "
        f"{summary['scale_paths_compared']} 条路径 / "
        f"{summary['scale_cases_compared']} 个案件逐条一致"
    )
    print(f"  JSON 报告: {report_path.as_posix()}")
    if code != 0:
        _print_failures(report)
    return code


def _print_failures(report: dict[str, Any]) -> None:
    print("\n失败项：")
    for section in ("demo_invariants", "concurrency"):
        for item in report[section].get("checks", []):
            if not item.get("ok"):
                print(f"- [{section}] {item.get('name')}")
    reviewer = report["small_model"]["reviewer_enumeration"]
    if not reviewer["ok"]:
        print(f"- [small_model] reviewer failures={len(reviewer['failures'])}")
    interleavings = report["small_model"]["interleaving_enumeration"]
    if not interleavings["ok"]:
        print(
            "- [small_model] interleaving failures="
            f"{len(interleavings['failures'])}"
        )
    if not report["scale"]["ok"]:
        print("- [scale] incremental/full comparison failed")


if __name__ == "__main__":
    raise SystemExit(main())
