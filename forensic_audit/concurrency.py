"""Deterministic two-thread race and local fault-injection checks.

One thread submits sign-offs; another advances evidence generations.  Barrier
gates make the short schedules deterministic.  A separate coordinator commits
revocations while a sign-off is paused immediately after validation, which is
the important committed-versus-preempted distinction.
"""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .engine import (
    AuditEngine,
    EvidenceRegistered,
    GenerationAdvanced,
    DelegationGranted,
    GrantRevoked,
    RootAuthorized,
    SignoffCommitted,
    SignoffRejected,
)
from .storage import DurableEventLog, FaultInjector, InjectedFault, recover_engine


@dataclass(frozen=True)
class SignoffRequest:
    signoff_id: str
    case_id: str
    evidence_id: str
    generation: int
    reviewer_id: str
    cost: int = 1
    intended_root_id: str | None = None
    intended_chain: tuple[str, ...] = ()


@dataclass(frozen=True)
class SubmissionResult:
    status: str
    seq: int | None = None
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class WorkerGate:
    """Barrier says the worker reached its commit point; event orders release."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self._barrier = threading.Barrier(2, timeout=timeout)
        self._release = threading.Event()

    def arrive(self) -> None:
        self._barrier.wait()
        if not self._release.wait(timeout=self.timeout):
            raise TimeoutError("worker was not released by coordinator")

    def wait_ready(self) -> None:
        self._barrier.wait()

    def allow_commit(self) -> None:
        self._release.set()


class ConcurrentAuditService:
    def __init__(
        self,
        path: str | Path | None = None,
        *,
        reset: bool = False,
        injector: FaultInjector | None = None,
    ) -> None:
        if path is None:
            self.log = DurableEventLog()
            self.engine = AuditEngine()
        else:
            path = Path(path)
            self.log = DurableEventLog.create(path, reset=reset)
            self.engine = recover_engine(path) if path.exists() else AuditEngine()
        self.lock = self.log.lock
        self.injector = injector

    def seed(self, event: Any) -> Any:
        """Append setup state without fault injection."""

        return self.log.append(event, self.engine, self.injector, inject=False)

    def revoke(self, grant_or_root_id: str) -> int:
        event = GrantRevoked(grant_or_root_id)
        committed = self.log.append(event, self.engine, self.injector, inject=False)
        return committed.seq

    def submit_signoff(
        self, request: SignoffRequest, gate: WorkerGate | None = None
    ) -> SubmissionResult:
        # First validation happens before the barrier so the coordinator knows
        # the request was viable when the race began.
        with self.lock:
            problem = self._signoff_problem_locked(request)
        if problem is not None:
            return self._reject(request, problem)

        if gate is not None:
            gate.arrive()

        # Commit-time revalidation is authoritative: events may have won the
        # race while this thread was paused.
        with self.lock:
            problem = self._signoff_problem_locked(request)
            if problem is not None:
                return self._reject(request, problem)

            event = SignoffCommitted(
                request.signoff_id,
                request.case_id,
                request.evidence_id,
                request.generation,
                request.reviewer_id,
                request.cost,
            )
            committed = self.log.append(event, self.engine, self.injector)
            return SubmissionResult("committed", committed.seq)

    def advance_generation(
        self,
        evidence_id: str,
        generation: int,
        gate: WorkerGate | None = None,
        fault_key: str | None = None,  # noqa: ARG002 - key derived from event
    ) -> SubmissionResult:
        with self.lock:
            if evidence_id not in self.engine.state_at().evidence:
                raise KeyError(f"unknown evidence: {evidence_id}")

        if gate is not None:
            gate.arrive()

        with self.lock:
            event = GenerationAdvanced(evidence_id, generation)
            committed = self.log.append(event, self.engine, self.injector)
            return SubmissionResult("committed", committed.seq)

    # -- internals ----------------------------------------------------------

    def _signoff_problem_locked(
        self, request: SignoffRequest
    ) -> tuple[str, dict[str, Any]] | None:
        state = self.engine.state_at()
        evidence = state.evidence.get(request.evidence_id)
        if evidence is None:
            return "EVIDENCE_UNKNOWN", {"evidence_id": request.evidence_id}
        if request.case_id not in evidence.cases:
            return "EVIDENCE_NOT_IN_CASE", {
                "case_id": request.case_id,
                "registered_cases": sorted(evidence.cases),
            }
        if evidence.generation != request.generation:
            return "PREEMPTED_BY_GENERATION", {
                "requested_generation": request.generation,
                "current_generation": evidence.generation,
            }
        if request.intended_root_id is not None:
            root = state.roots.get(request.intended_root_id)
            if root is None:
                return "ROOT_NOT_AUTHORIZED", {
                    "root_id": request.intended_root_id
                }
            if request.intended_root_id in state.revocations:
                return "PREEMPTED_BY_REVOCATION", {
                    "revoked_id": request.intended_root_id,
                    "revoked_at": state.revocations[request.intended_root_id],
                }
        for grant_id in request.intended_chain:
            if grant_id in state.revocations:
                return "PREEMPTED_BY_REVOCATION", {
                    "revoked_id": grant_id,
                    "revoked_at": state.revocations[grant_id],
                }
            if grant_id not in state.grants:
                return "GRANT_UNKNOWN", {"grant_id": grant_id}
        return None

    def _reject(
        self,
        request: SignoffRequest,
        problem: tuple[str, dict[str, Any]],
    ) -> SubmissionResult:
        code, detail = problem
        event = SignoffRejected(
            request.signoff_id,
            request.case_id,
            request.evidence_id,
            request.generation,
            request.reviewer_id,
            code,
            detail,
        )
        committed = self.log.append(event, self.engine, self.injector, inject=False)
        status = "preempted" if code.startswith("PREEMPTED_") else "rejected"
        return SubmissionResult(status, committed.seq, code, detail)


class SignoffWorker(threading.Thread):
    def __init__(
        self,
        service: ConcurrentAuditService,
        request: SignoffRequest,
        gate: WorkerGate | None = None,
        name: str = "signoff-worker",
    ) -> None:
        super().__init__(name=name, daemon=True)
        self.service = service
        self.request = request
        self.gate = gate
        self.result: SubmissionResult | None = None
        self.error: BaseException | None = None

    def run(self) -> None:  # noqa: D401 - thread entry point
        try:
            self.result = self.service.submit_signoff(self.request, self.gate)
        except BaseException as exc:  # captured and asserted by the race lab
            self.error = exc


class GenerationWorker(threading.Thread):
    def __init__(
        self,
        service: ConcurrentAuditService,
        evidence_id: str,
        generation: int,
        gate: WorkerGate | None = None,
        name: str = "generation-worker",
    ) -> None:
        super().__init__(name=name, daemon=True)
        self.service = service
        self.evidence_id = evidence_id
        self.generation = generation
        self.gate = gate
        self.result: SubmissionResult | None = None
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.result = self.service.advance_generation(
                self.evidence_id, self.generation, self.gate
            )
        except BaseException as exc:
            self.error = exc


def new_race_service(
    path: str | Path | None = None,
    *,
    reset: bool = True,
    injector: FaultInjector | None = None,
) -> tuple[ConcurrentAuditService, SignoffRequest]:
    service = ConcurrentAuditService(path, reset=reset, injector=injector)
    service.seed(EvidenceRegistered("EV-RACE", ("CASE-RACE",), 1))
    service.seed(RootAuthorized("ROOT-R1", "ctl-r1", "CASE-RACE"))
    service.seed(RootAuthorized("ROOT-R2", "ctl-r2", "CASE-RACE"))
    service.seed(
        DelegationGranted(
            "G-R1", "ROOT-R1", "CASE-RACE", "ctl-r1", "reviewer-a", cost=0
        )
    )
    service.seed(
        DelegationGranted(
            "G-R2", "ROOT-R2", "CASE-RACE", "ctl-r2", "reviewer-b", cost=0
        )
    )
    service.seed(
        SignoffCommitted(
            "SIG-B-SETTLED", "CASE-RACE", "EV-RACE", 1, "reviewer-b", cost=1
        )
    )
    request = SignoffRequest(
        "SIG-A-RACE",
        "CASE-RACE",
        "EV-RACE",
        1,
        "reviewer-a",
        cost=1,
        intended_root_id="ROOT-R1",
        intended_chain=("G-R1",),
    )
    return service, request


def run_concurrency_checks(workdir: str | Path) -> dict[str, Any]:
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, Any]] = []

    def record(name: str, ok: bool, **detail: Any) -> None:
        checks.append({"name": name, "ok": bool(ok), **detail})

    # 1. Sign-off commits, then revocation arrives: old watermark stays valid.
    path = workdir / "01-committed-before-revocation.jsonl"
    service, request = new_race_service(path)
    gate = WorkerGate()
    worker = SignoffWorker(service, request, gate)
    worker.start()
    gate.wait_ready()
    gate.allow_commit()
    worker.join(10)

    sign_result = worker.result
    sign_error = _error_detail(worker.error)
    sign_seq = sign_result.seq if sign_result else None
    revoke_seq: int | None = None
    historical = None
    current = None
    recovered_has_signoff = False
    if worker.error is None and sign_result is not None and sign_seq is not None:
        revoke_seq = service.revoke("G-R1")
        historical = service.engine.evaluate(
            "CASE-RACE", "EV-RACE", sign_seq
        ).to_jsonable()
        current_decision = service.engine.evaluate("CASE-RACE", "EV-RACE")
        current = current_decision.to_jsonable()
        recovered = recover_engine(path)
        recovered_has_signoff = "SIG-A-RACE" in recovered.state_at().signoffs

    record(
        "committed_signoff_precedes_revocation_and_is_historical_proof",
        worker.error is None
        and sign_result is not None
        and sign_result.status == "committed"
        and sign_seq is not None
        and revoke_seq is not None
        and sign_seq < revoke_seq
        and historical is not None
        and historical["releasable"] is True
        and current is not None
        and current["releasable"] is False
        and recovered_has_signoff,
        signoff=sign_result.__dict__ if sign_result else None,
        signoff_error=sign_error,
        signoff_seq=sign_seq,
        revocation_seq=revoke_seq,
        historical_releasable=historical["releasable"] if historical else None,
        current_releasable=current["releasable"] if current else None,
        current_reasons=[r["code"] for r in current["reasons"]] if current else None,
        recovered_has_signoff=recovered_has_signoff,
    )

    # 2. Injected fault after durable commit: caller sees failure, but the
    #    commit is committed and recovery must replay it.
    path = workdir / "02-fault-after-commit.jsonl"
    injector = FaultInjector(after_commit={"SIG-A-RACE"})
    service, request = new_race_service(path, injector=injector)
    worker = SignoffWorker(service, request)
    worker.start()
    worker.join(10)
    after_fault = worker.error
    after_ok = (
        isinstance(after_fault, InjectedFault)
        and after_fault.phase == "after_commit"
        and after_fault.committed is True
        and after_fault.seq is not None
        and "SIG-A-RACE" in recover_engine(path).state_at().signoffs
    )
    record(
        "fault_after_commit_still_committed_and_recoverable",
        after_ok,
        error=_error_detail(after_fault),
        injector_events=list(injector.events),
    )

    # 3. Injected fault before commit: no durable sign-off exists.
    path = workdir / "03-fault-before-commit.jsonl"
    injector = FaultInjector(before_commit={"SIG-A-RACE"})
    service, request = new_race_service(path, injector=injector)
    before_fault: BaseException | None = None
    try:
        service.submit_signoff(request)
    except BaseException as exc:  # expected injected fault
        before_fault = exc
    before_ok = (
        isinstance(before_fault, InjectedFault)
        and before_fault.phase == "before_commit"
        and before_fault.committed is False
        and "SIG-A-RACE" not in recover_engine(path).state_at().signoffs
    )
    record(
        "fault_before_commit_leaves_no_signoff",
        before_ok,
        error=_error_detail(before_fault),
        injector_events=list(injector.events),
    )

    # 4. Revocation wins the race while sign-off is paused.
    path = workdir / "04-revocation-preempts-signoff.jsonl"
    service, request = new_race_service(path)
    gate = WorkerGate()
    worker = SignoffWorker(service, request, gate)
    worker.start()
    gate.wait_ready()
    revoke_seq = service.revoke("G-R1")
    gate.allow_commit()
    worker.join(10)

    preempt_result = worker.result
    preempt_error = _error_detail(worker.error)
    recovered = recover_engine(path)
    state = recovered.state_at()
    committed_after_preempt = "SIG-A-RACE" in state.signoffs
    rejection_present = any(
        isinstance(e, SignoffRejected) and e.signoff_id == "SIG-A-RACE"
        for e in recovered.events
    )
    record(
        "revocation_commits_first_and_preempts_signoff",
        worker.error is None
        and preempt_result is not None
        and preempt_result.status == "preempted"
        and preempt_result.reason == "PREEMPTED_BY_REVOCATION"
        and preempt_result.seq is not None
        and revoke_seq < preempt_result.seq
        and not committed_after_preempt
        and rejection_present,
        result=preempt_result.__dict__ if preempt_result else None,
        error=preempt_error,
        revocation_seq=revoke_seq,
        committed_signoff=committed_after_preempt,
        rejection_audit_record=rejection_present,
    )

    # 5/6. Real two-thread sign-off vs evidence-generation schedules.
    schedule_details: dict[str, Any] = {}
    for order in ("signoff_first", "generation_first"):
        path = workdir / f"05-{order}.jsonl"
        service, request = new_race_service(path)
        sign_gate = WorkerGate()
        gen_gate = WorkerGate()
        sign_worker = SignoffWorker(service, request, sign_gate)
        gen_worker = GenerationWorker(service, "EV-RACE", 2, gen_gate)

        sign_worker.start()
        gen_worker.start()
        sign_gate.wait_ready()
        gen_gate.wait_ready()

        detail: dict[str, Any] = {}
        if order == "signoff_first":
            sign_gate.allow_commit()
            sign_worker.join(10)
            sign_result = sign_worker.result
            sign_seq = sign_result.seq if sign_result else None
            detail["signoff"] = sign_result.__dict__ if sign_result else None
            detail["signoff_error"] = _error_detail(sign_worker.error)

            gen_gate.allow_commit()
            gen_worker.join(10)
            detail["generation"] = (
                gen_worker.result.__dict__ if gen_worker.result else None
            )
            detail["generation_error"] = _error_detail(gen_worker.error)
            if sign_seq is not None:
                detail["at_signoff_watermark"] = service.engine.evaluate(
                    "CASE-RACE", "EV-RACE", sign_seq
                ).releasable
            final = service.engine.evaluate("CASE-RACE", "EV-RACE")
            detail["final_releasable"] = final.releasable
            detail["final_reason_codes"] = [r.code for r in final.reasons]
            ok = (
                sign_worker.error is None
                and gen_worker.error is None
                and sign_result is not None
                and sign_result.status == "committed"
                and detail.get("at_signoff_watermark") is True
                and detail["final_releasable"] is False
                and "STALE_GENERATION" in detail["final_reason_codes"]
            )
        else:
            gen_gate.allow_commit()
            gen_worker.join(10)
            detail["generation"] = (
                gen_worker.result.__dict__ if gen_worker.result else None
            )
            detail["generation_error"] = _error_detail(gen_worker.error)

            sign_gate.allow_commit()
            sign_worker.join(10)
            detail["signoff"] = (
                sign_worker.result.__dict__ if sign_worker.result else None
            )
            detail["signoff_error"] = _error_detail(sign_worker.error)
            result = sign_worker.result
            ok = (
                gen_worker.error is None
                and sign_worker.error is None
                and result is not None
                and result.status == "preempted"
                and result.reason == "PREEMPTED_BY_GENERATION"
                and "SIG-A-RACE"
                not in recover_engine(path).state_at().signoffs
            )

        detail["threads_alive"] = {
            "signoff": sign_worker.is_alive(),
            "generation": gen_worker.is_alive(),
        }
        schedule_details[order] = detail
        record(f"two_thread_generation_race_{order}", ok, **detail)

    ok_all = all(item["ok"] for item in checks)
    return {
        "ok": ok_all,
        "check_count": len(checks),
        "passed_count": sum(1 for c in checks if c["ok"]),
        "workdir": str(workdir),
        "checks": checks,
        "schedules": schedule_details,
    }


def _error_detail(error: BaseException | None) -> dict[str, Any] | None:
    if error is None:
        return None
    detail: dict[str, Any] = {
        "type": type(error).__name__,
        "message": str(error),
    }
    if isinstance(error, InjectedFault):
        detail.update(
            {"phase": error.phase, "committed": error.committed, "seq": error.seq}
        )
    detail["traceback_tail"] = traceback.format_exception_only(
        type(error), error
    )[-1].strip()
    return detail
