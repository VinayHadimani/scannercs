"""FastAPI service exposing the TRIAD_Scanner.

POST /scan  {"target": "<github repo or website url>", "demo": optional bool}
GET  /health

DEMO_MODE: set env TRIAD_DEMO_MODE=1 (or pass "demo": true) to scan the
bundled fixtures instantly with zero network - the real engine still runs,
only the TARGET is mocked.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel

from triad_scanner import TRIAD_Scanner

app = FastAPI(
    title="TRIAD Scanner",
    version="1.1.0",
    description="Single-input vulnerability scanner: GitHub repo URL -> "
                "dependency CVEs (Trivy-derived); live website URL -> "
                "template checks (Nuclei-derived) + passive rules "
                "(ZAP-derived).",
)
_scanner = TRIAD_Scanner()


class ScanRequest(BaseModel):
    target: str
    demo: Optional[bool] = None      # default: env TRIAD_DEMO_MODE, else True


def _resolve_demo(req: "ScanRequest") -> bool:
    """Per-request demo override > TRIAD_DEMO_MODE env > safe default ON.

    The safe default keeps live demos crash-proof: unknown targets fall back
    to the bundled fixtures. Pass {"demo": false} for a real live scan.
    """
    if req.demo is not None:
        return req.demo
    return os.environ.get("TRIAD_DEMO_MODE", "1") == "1"


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": app.version,
        "demo_mode": os.environ.get("TRIAD_DEMO_MODE", "0") == "1",
        "templates": len(_scanner.templates),
    }


@app.post("/scan")
def scan(req: ScanRequest) -> dict:
    return _scanner.scan(req.target, demo=_resolve_demo(req))
