"""Local audit for case-isolated forensic evidence release.

The package uses only the Python 3.12 standard library.  The important
invariant is that a release needs two seats traced to two distinct underlying
controllers/root authorizations for the requesting case and current evidence
generation.
"""

from .engine import (
    AuditEngine,
    BlockReason,
    Decision,
    Proof,
    Seat,
    build_demo_engine,
)

__all__ = [
    "AuditEngine",
    "BlockReason",
    "Decision",
    "Proof",
    "Seat",
    "build_demo_engine",
]
