"""TRIAD_Scanner: a lightweight unified vulnerability scanner.

Synthesized by reverse-engineering the core detection mechanisms of three
industry tools (see README for per-lane provenance):

  * Trivy  (aquasecurity/trivy)  -> dependency manifest parsing + CVE matching
  * Nuclei (projectdiscovery)    -> YAML template engine (matchers/extractors)
  * ZAP     (zaproxy)            -> passive HTTP response security rules

Single input, automatic routing:
  GitHub repo URL  -> dependency lane (Trivy-derived)
  Live website URL -> template lane (Nuclei-derived) + passive lane (ZAP-derived)

DEMO_MODE: mocks the TARGET (fixture data), never the ENGINE. The real
matching code always runs; only the HTTP responses / repo files are faked,
instantly, with zero network.

Every finding carries: cve_id, target_url, severity, source_tool, description
(+ optional cwe, evidence, fix) ready for TRIAD's INGEST -> ENRICH (NVD/EPSS)
-> FUSE -> EXPLAIN pipeline.
"""
from __future__ import annotations

import json
import os
import re
import tarfile
import time
import urllib.request
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INDEX = os.path.join(_HERE, "data", "dep_cve_index.json")
DEFAULT_TEMPLATES = os.path.join(_HERE, "triad_templates")
DEFAULT_DEMO_DIR = os.path.join(_HERE, "data", "demo")

_GITHUB_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------
def classify_target(target: str) -> tuple[str, str]:
    """Route the input. Returns (kind, normalized) with kind in
    {"github", "web", "local", "invalid"}."""
    target = (target or "").strip()
    if not target:
        return "invalid", ""
    if os.path.isdir(target):
        return "local", os.path.abspath(target)
    m = _GITHUB_RE.match(target)
    if m:
        owner, repo = m.group(1), m.group(2)
        return "github", f"https://github.com/{owner}/{repo}"
    if target.lower().startswith(("http://", "https://")):
        return "web", target
    if re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}(:\d+)?(/.*)?$", target):
        return "web", "https://" + target          # bare host -> https
    return "invalid", target


# --------------------------------------------------------------------------
# Version engine (trivy-derived)
# SemVer for npm, PEP440-lite for pip; constraint grammar from trivy-db
# range.go output: ">=X, <Y" groups OR-joined across list entries.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class _V:
    """Parsed version. tuple ordering per scheme."""
    scheme: str
    release: tuple
    pre: tuple | None = None      # ('rc', 1) style identifiers
    post: int | None = None


def _parse_semver(v: str) -> _V:
    v = v.strip().lstrip("vV")
    core, _, _build = v.partition("+")
    core, _, pre = core.partition("-")
    nums = []
    for part in core.split("."):
        m = re.match(r"^(\d+)", part)
        nums.append(int(m.group(1)) if m else 0)
    while len(nums) < 3:
        nums.append(0)
    pre_ids = tuple(pre.split(".")) if pre else None
    return _V("semver", tuple(nums[:3]), pre_ids)


def _parse_pep440(v: str) -> _V:
    v = v.strip().lstrip("vV").split("+")[0]
    m = re.match(r"^(\d+(?:\.\d+)*)", v)
    release = tuple(int(x) for x in m.group(1).split(".")) if m else (0,)
    rest = v[m.end():] if m else ""
    pre, post = None, None
    pm = re.match(r"^(a|b|rc|c)(\d+)?", rest)
    if pm:
        pre = (pm.group(1), int(pm.group(2) or 0))
    else:
        dm = re.search(r"\.?dev(\d+)?", rest)
        if dm:
            pre = ("dev", int(dm.group(1) or 0))
    pom = re.search(r"\.?post(\d+)?", rest)
    if pom:
        post = int(pom.group(1) or 0)
    return _V("pep440", release, pre, post)


def _parse_any(v: str, scheme: str) -> _V:
    if scheme == "pep440":
        return _parse_pep440(v)
    return _parse_semver(v)


_PEP_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "rc": 2, "c": 2, "pre": 2}


def _cmp(a: _V, b: _V) -> int:
    """Three-way compare honoring per-scheme prerelease/post rules."""
    ra, rb = list(a.release), list(b.release)
    n = max(len(ra), len(rb))
    ra += [0] * (n - len(ra))
    rb += [0] * (n - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1
    # release equal -> prerelease / post ordering
    if a.scheme == "semver":
        if a.pre is None and b.pre is None:
            pass
        elif a.pre is None:
            return 1                       # final > prerelease
        elif b.pre is None:
            return -1
        else:
            c = _cmp_pre_ids(a.pre, b.pre)
            if c:
                return c
    else:
        ka, kb = _pep_pre_key(a.pre), _pep_pre_key(b.pre)
        if ka != kb:
            return -1 if ka < kb else 1
    if (a.post or 0) != (b.post or 0):
        return -1 if (a.post or 0) < (b.post or 0) else 1
    return 0


def _cmp_pre_ids(pa: tuple, pb: tuple) -> int:
    """npm semver prerelease identifier ordering: numeric < alphanumeric."""
    for i in range(max(len(pa), len(pb))):
        if i >= len(pa):
            return -1
        if i >= len(pb):
            return 1
        x, y = pa[i], pb[i]
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return -1 if int(x) < int(y) else 1
        if xn:
            return -1
        if yn:
            return 1
        return -1 if x < y else 1
    return 0


def _pep_pre_key(pre: tuple | None) -> tuple:
    """PEP440: dev < a < b < rc < final."""
    if pre is None:
        return (2, 0, 0)
    k, n = pre[0], pre[1] if len(pre) > 1 else 0
    if k == "dev":
        return (0, 0, n)
    return (1, _PEP_PRE_RANK.get(k, 2), n)


def _next_nonzero_bump(rel: tuple) -> tuple:
    """npm caret upper bound: bump the first nonzero component, zero the rest."""
    r = list(rel) + [0] * (3 - len(rel))
    for i in range(3):
        if r[i] != 0:
            r[i] += 1
            return tuple(r[:i + 1]) + (0,) * (2 - i)
    return (r[0] + 1, 0, 0)


def _satisfies(v: _V, op: str, t: _V) -> bool:
    c = _cmp(v, t)
    if op in ("=", "=="):
        return c == 0
    if op == "!=":
        return c != 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op in ("~", "~="):                   # npm tilde / pep440 ~=
        if c < 0:
            return False
        vrel = list(v.release) + [0] * (3 - len(v.release))
        trel = list(t.release) + [0] * (3 - len(t.release))
        if vrel[0] != trel[0]:
            return False
        if len(t.release) >= 2 and vrel[1] != trel[1]:
            return False
        return True
    if op == "^":                           # npm caret
        if c < 0:
            return False
        upper = _next_nonzero_bump(t.release)
        return _cmp(v, _V(t.scheme, upper)) < 0
    raise ValueError(f"unsupported operator: {op!r}")


_CONSTRAINT_RE = re.compile(
    r"^\s*(>=|<=|==|!=|~=|=|>|<|\^|~)\s*v?([0-9][0-9A-Za-z.\-+]*)")


def matches_constraints(version: str, constraints: str,
                        scheme: str = "semver") -> bool:
    """True if `version` satisfies the trivy-db style constraint string.
    Groups separated by '||' (OR); within a group, comma-separated AND."""
    v = _parse_any(version, scheme)
    for group in re.split(r"\|\|", constraints or ""):
        group = group.strip()
        if not group or group == "*":
            return True                     # empty constraint matches everything
        ok = True
        for c in group.split(","):
            c = c.strip()
            if not c:
                continue
            m = _CONSTRAINT_RE.match(c)
            if not m:
                raise ValueError(f"unparseable constraint: {c!r}")
            if not _satisfies(v, m.group(1), _parse_any(m.group(2), scheme)):
                ok = False
                break
        if ok:
            return True
    return False


def is_vulnerable(version: str, ranges: list[str] | None,
                  patched: list[str] | None = None,
                  scheme: str = "semver") -> bool:
    """Port of trivy compare.IsVulnerable: fail-open on empty ranges (no
    range info -> treat as affected), vulnerable if ANY OR-group matches,
    exact `patched` versions always excluded."""
    ranges = [r for r in (ranges or []) if r and r.strip()]
    if not ranges:
        return True
    v = _parse_any(version, scheme)
    if patched:
        for p in patched:
            if _cmp(v, _parse_any(p, scheme)) == 0:
                return False
    for group in ranges:
        try:
            if matches_constraints(version, group, scheme):
                return True
        except ValueError:
            continue                        # unparsable constraint -> skip group
    return False


def normalize_pkg_name(name: str, eco: str) -> str:
    """trivy NormalizePkgName: pip lowercases and maps '_' -> '-'."""
    name = (name or "").strip()
    if eco == "pip":
        return name.lower().replace("_", "-")
    return name
