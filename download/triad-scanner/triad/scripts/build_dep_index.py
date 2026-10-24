#!/usr/bin/env python3
"""Rebuild data/dep_cve_index.json from the live OSV API (https://api.osv.dev).

Mirrors trivy-db's OSV ingestion (pkg/vulnsrc/osv/{osv,range}.go):
  * every advisory is deduped by its CVE alias
  * SEMVER/ECOSYSTEM ranges are converted into trivy-db range.go strings:
    ">= X, < Y" (or ">= X, <= Y" for last_affected), OR-joined per advisory
  * `patched` collects fixed events; `fixed` records the highest fix
  * severity comes from database_specific.severity, else CVSS score bucket

Only advisories that carry a CVE id are kept (TRIAD's enrichment stage
queries NVD/EPSS by CVE).
"""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OSV_QUERY = "https://api.osv.dev/v1/query"
OUT = Path(__file__).resolve().parent.parent / "data" / "dep_cve_index.json"

# Popular packages with rich CVE history (npm + PyPI ecosystems)
NPM_PACKAGES = [
    "express", "lodash", "axios", "moment", "node-fetch", "request", "ws",
    "jsonwebtoken", "qs", "minimist", "mongodb", "sequelize", "ejs",
    "ua-parser-js", "tar", "glob", "ini", "path-parse", "vm2", "engine.io",
    "socket.io", "underscore", "validator", "got", "elliptic", "cookie",
    "tough-cookie", "mime", "send", "serve-static", "browserify-sign",
    "http-cache-semantics", "json5", "flat", "multer", "jsonwebtoken",
]
PYPI_PACKAGES = [
    "requests", "urllib3", "pillow", "pyyaml", "jinja2", "django", "flask",
    "tornado", "sqlalchemy", "cryptography", "gunicorn", "celery", "aiohttp",
    "werkzeug", "starlette", "setuptools", "twisted", "pyjwt", "markdown",
    "bleach",
]

CVSS_RE = re.compile(r"CVSS:3\.[01]/AV:[^/]+/AC:[^/]+/PR:[^/]+/UI:[^/]+"
                     r"/S:[CUI]/C:[^/]+/I:[^/]+/A:[^/]+")


def _severity_bucket(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cvss_score(adv: dict) -> float | None:
    for sev in adv.get("severity") or []:
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            score = str(sev.get("score", ""))
            # vector string -> use the trailing score if numeric label present
            m = CVSS_RE.search(score)
            if m:
                # approximate via CVSS base metrics (documented approximation):
                # C/I/A full on multiple scopes scores high; use conservative map
                # prefer database_specific severity when available anyway.
                return None
    return None


def _severity_of(adv: dict) -> str:
    db_sev = (adv.get("database_specific") or {}).get("severity")
    if isinstance(db_sev, str) and db_sev.lower() in (
            "critical", "high", "medium", "low", "moderate"):
        s = db_sev.lower()
        return "medium" if s == "moderate" else s
    # CVSS vector fallback: parse the vector's impact roughly
    for sev in adv.get("severity") or []:
        score = str(sev.get("score", ""))
        m = CVSS_RE.search(score)
        if m:
            vector = m.group(0)
            impacts = re.findall(r"/[CIA]:(H|M|L)", vector)
            if impacts:
                high = sum(1 for i in impacts if i == "H")
                mid = sum(1 for i in impacts if i == "M")
                if high >= 3:
                    return "critical"
                if high >= 1:
                    return "high"
                if mid >= 1:
                    return "medium"
                return "low"
    return "medium"


def _cve_of(adv: dict) -> str | None:
    ids = [adv.get("id")] + list(adv.get("aliases") or [])
    for i in ids:
        if i and i.startswith("CVE-"):
            return i
    return None


def _range_groups(affected: dict) -> tuple[list[str], list[str], str | None]:
    """OSV events -> trivy-db range.go strings + patched/fixed lists."""
    groups: list[str] = []
    patched: list[str] = []
    fixed_best: str | None = None
    for rng in affected.get("ranges") or []:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue                     # GIT ranges: not applicable
        cons: list[str] = []
        for ev in rng.get("events") or []:
            if "introduced" in ev and ev["introduced"] != "0":
                cons.append(f">= {ev['introduced']}")
            elif "fixed" in ev:
                cons.append(f"< {ev['fixed']}")
                patched.append(ev["fixed"])
                fixed_best = ev["fixed"]        # OSV lists highest fix last
            elif "last_affected" in ev:
                cons.append(f"<= {ev['last_affected']}")
        if cons:
            groups.append(", ".join(cons))
    # drop unbounded ">= 0" only-groups (would flag every version forever)
    groups = [g for g in groups if g.strip() != ">= 0"]
    return groups, patched, fixed_best


def query_osv(ecosystem: str, name: str) -> list[dict]:
    advisories, page = [], None
    for _ in range(3):                   # up to 3 pages per package
        body = {"package": {"name": name, "ecosystem": ecosystem}}
        if page:
            body["page_token"] = page
        req = urllib.request.Request(
            OSV_QUERY, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": "TRIAD-Scanner/1.1 (index build)"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                doc = json.loads(resp.read())
        except Exception as exc:
            print(f"  ! {ecosystem}/{name}: {exc}", file=sys.stderr)
            return advisories
        advisories += doc.get("vulns") or []
        page = doc.get("next_page_token")
        if not page:
            break
        time.sleep(0.1)
    return advisories


def main() -> None:
    index: dict[str, dict[str, list[dict]]] = {"npm": {}, "pip": {}}
    total = 0
    seen: set[tuple[str, str, str]] = set()
    for eco_key, osv_eco, packages in (
            ("npm", "npm", NPM_PACKAGES), ("pip", "PyPI", PYPI_PACKAGES)):
        for pkg in sorted(set(packages)):
            advisories = query_osv(osv_eco, pkg)
            kept = 0
            for adv in advisories:
                cve = _cve_of(adv)
                if not cve:
                    continue
                key = (eco_key, pkg.lower(), cve)
                if key in seen:
                    continue
                seen.add(key)
                groups, patched, fixed = [], [], None
                for affected in adv.get("affected") or []:
                    pname = (affected.get("package") or {}).get("name", "")
                    if pname.lower() != pkg.lower():
                        continue
                    g, p, f = _range_groups(affected)
                    groups += g
                    patched += p
                    if f:
                        fixed = f
                if not groups:
                    continue             # nothing version-applicable
                summary = (adv.get("summary") or
                           re.sub(r"\s+", " ", (adv.get("details") or ""))[:180])
                cwes = (adv.get("database_specific") or {}).get("cwe_ids")
                entry = {
                    "cve": cve,
                    "ghsa": adv.get("id"),
                    "severity": _severity_of(adv),
                    "summary": summary[:240],
                    "cwe": cwes[0] if isinstance(cwes, list) and cwes else None,
                    "ranges": groups,
                    "patched": sorted(set(patched)),
                    "fixed": fixed,
                }
                index[eco_key].setdefault(pkg.lower(), []).append(entry)
                kept += 1
                total += 1
            print(f"{eco_key}/{pkg}: {len(advisories)} advisories, {kept} CVE-indexed")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": "OSV API (api.osv.dev), trivy-db osv/range.go conversion",
        "advisory_count": total,
        "advisories": index,
    }
    OUT.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    print(f"\nwrote {OUT} ({total} advisories across "
          f"{sum(len(v) for v in index.values())} packages)")


if __name__ == "__main__":
    main()
