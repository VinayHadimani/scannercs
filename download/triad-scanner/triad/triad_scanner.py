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
        # bare "github.com/owner/repo" is unambiguous -> dependency lane
        gm = re.match(r"^(?:www\.)?github\.com(/.+)$", target, re.I)
        if gm:
            seg = [s for s in gm.group(1).strip("/").split("/") if s and s != ".git"]
            if len(seg) >= 2:
                return "github", f"https://github.com/{seg[0]}/{seg[1].removesuffix('.git')}"
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
            if not m:                      # bare version pin: "1.2.3" == "= 1.2.3"
                bm = re.match(r"^v?([0-9][0-9A-Za-z.\-+]*)$", c)
                if not bm:
                    raise ValueError(f"unparseable constraint: {c!r}")
                op, ver = "=", bm.group(1)
            else:
                op, ver = m.group(1), m.group(2)
            if not _satisfies(v, op, _parse_any(ver, scheme)):
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


# --------------------------------------------------------------------------
# Manifest parsers (trivy-derived: package.json / requirements.txt / pyproject)
# --------------------------------------------------------------------------
def _lower_bound(spec: str) -> str | None:
    """Approximate a range spec by its lower bound (exact pins preferred).
    trivy itself keeps the raw range; for CVE matching the conservative
    approximation documents our deliberate subset (see README)."""
    spec = (spec or "").strip()
    if not spec or spec in ("*", "latest", "next"):
        return None
    if any(ch in spec for ch in ":/\\") or spec.startswith(("workspace", "npm:",
                                                            "file:", "git",
                                                            "http://", "https://")):
        return None                          # non-registry spec, skip
    m = re.search(r"\d[0-9A-Za-z.\-+]*", spec)
    return m.group(0) if m else None


def parse_package_json(text: str) -> list[tuple[str, str, str]]:
    """Port of trivy pkg/dependency/parser/nodejs/packagejson+npm: returns
    (name, version, eco) for every registry-resolvable dependency."""
    doc = json.loads(text)
    out: list[tuple[str, str, str]] = []
    if not isinstance(doc, dict):
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            ver = _lower_bound(spec)
            if ver:
                out.append((name, ver, "npm"))
    return out


def parse_requirements_txt(text: str) -> list[tuple[str, str, str]]:
    """Port of trivy pkg/dependency/parser/python/pip: name + pinned (==) or
    lower-bound version; extras/comments/includes handled."""
    out: list[tuple[str, str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = re.sub(r"\s*\[[^\]]*\]", "", line)        # extras: pkg[x]
        line = line.split(";", 1)[0].strip()             # env markers
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(2).strip()
        if spec.startswith("=="):
            ver = spec[2:].strip().split(",")[0].strip()
        elif spec:
            ver = _lower_bound(spec)
        else:
            ver = None
        if ver:
            out.append((name, ver, "pip"))
    return out


def parse_pyproject_toml(text: str) -> list[tuple[str, str, str]]:
    """PEP 621 [project].dependencies + optional-dependencies, plus poetry
    [tool.poetry.dependencies] (trivy parses both formats)."""
    import tomllib
    doc = tomllib.loads(text)
    out: list[tuple[str, str, str]] = []

    def _add(name: str, spec: str):
        ver = _lower_bound(str(spec)) if spec else None
        if ver:
            out.append((name, ver, "pip"))

    project = doc.get("project") or {}
    for dep in list(project.get("dependencies") or []):
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", str(dep))
        if m:
            _add(m.group(1), m.group(2))
    for group in (project.get("optional-dependencies") or {}).values():
        for dep in group:
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", str(dep))
            if m:
                _add(m.group(1), m.group(2))
    poetry = ((doc.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name, spec in poetry.items():
        if name == "python":
            continue
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        _add(name, str(spec or ""))
    return out


MANIFEST_PARSERS = {
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
}


# --------------------------------------------------------------------------
# Dependency lane (trivy-derived DetectVulnerabilities flow)
# --------------------------------------------------------------------------
class DependencyLane:
    """Matches manifest dependencies against the OSV-derived CVE index using
    trivy's IsVulnerable semantics (fail-open ranges, OR-groups, patched
    exclusion) and trivy-db's range.go range strings."""

    def __init__(self, index_path: str = DEFAULT_INDEX):
        with open(index_path, encoding="utf-8") as fh:
            data = json.load(fh)
        self.advisories: dict[str, dict[str, list[dict]]] = data.get("advisories", {})

    def scan_manifests(self, files: dict[str, str], target_url: str) -> list[dict]:
        findings: list[dict] = []
        seen: set[tuple] = set()
        for rel in sorted(files):
            parser = MANIFEST_PARSERS.get(os.path.basename(rel))
            if parser is None:
                continue
            try:
                deps = parser(files[rel])
            except Exception:
                continue                     # unparsable manifest -> skip file
            for name, version, eco in deps:
                for adv in self._match_package(name, version, eco, target_url, rel):
                    key = (adv["cve_id"], name, version, rel)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(adv)
        return findings

    def _match_package(self, name: str, version: str, eco: str,
                       target_url: str, manifest: str) -> list[dict]:
        eco_map = self.advisories.get(eco) or {}
        entries = eco_map.get(normalize_pkg_name(name, eco)) or []
        scheme = "semver" if eco == "npm" else "pep440"
        target = f"{target_url.rstrip('/')}/{manifest}" if manifest else target_url
        out: list[dict] = []
        for adv in entries:
            try:
                if not is_vulnerable(version, adv.get("ranges"),
                                     adv.get("patched"), scheme):
                    continue
            except ValueError:
                continue
            fixed = adv.get("fixed")
            fix_note = f" Upgrade to {fixed} or later." if fixed else ""
            out.append({
                "cve_id": adv.get("cve"),
                "target_url": target,
                "severity": (adv.get("severity") or "medium").lower(),
                "source_tool": "triad-derived",
                "description": f"{name} {version} is affected by {adv.get('cve')}: "
                               f"{adv.get('summary', 'vulnerable package version')}"
                               f" (fixed in {fixed}).{fix_note} "
                               "Ready for NVD/EPSS enrichment.",
                "cwe": adv.get("cwe"),
                "evidence": f"{name}@{version} in {manifest}",
                "fix": fixed,
            })
        return out


# --------------------------------------------------------------------------
# Template engine (nuclei-derived): YAML templates -> matchers/extractors
# --------------------------------------------------------------------------
def load_templates(templates_dir: str = DEFAULT_TEMPLATES) -> list[dict]:
    import yaml  # kept local so the dependency lane works without PyYAML
    out = []
    for fname in sorted(os.listdir(templates_dir)):
        if not fname.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(templates_dir, fname), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        doc["_path"] = os.path.join(templates_dir, fname)
        out.append(doc)
    return out


def _interpolate(path: str, base_url: str) -> str:
    """Port of nuclei BaseURL-style variable substitution (subset)."""
    from urllib.parse import urlsplit
    u = urlsplit(base_url)
    root = f"{u.scheme}://{u.netloc}"
    vals = {
        "{{BaseURL}}": base_url.rstrip("/"),
        "{{RootURL}}": root,
        "{{Host}}": u.netloc,
        "{{Scheme}}": u.scheme,
    }
    for k, v in vals.items():
        path = path.replace(k, v)
    return path


def build_event(resp: Any) -> dict:
    """Port of nuclei pkg/protocols/http/operators.go responseToDSLMap:
    body / header / response / status_code / content_length plus every header
    lowercased with '-'->'_' and cookies by name."""
    raw = resp["raw"]
    header_blob, _, body = raw.partition("\r\n\r\n")
    status_line = raw.split("\r\n", 1)[0] if raw else ""
    headers: dict[str, list[str]] = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    event: dict[str, Any] = {
        "body": body,
        "header": "\r\n".join(f"{k}: {', '.join(v)}" for k, v in headers.items()),
        "all_headers": "\r\n".join(f"{k}: {', '.join(v)}" for k, v in headers.items()),
        "response": raw,
        "status_code": resp["status"],
        "content_length": len(body),
        "matched": resp.get("matched", base_url_of(resp)),
        "request": resp.get("request", ""),
        "_status_line": status_line,
        "_status_ok": 200 <= resp["status"] < 400,
    }
    for k, v in headers.items():
        event[k.replace("-", "_")] = ", ".join(v)
    for c in resp.get("cookies") or []:
        name, _, val = c.partition("=")
        event.setdefault(name.strip().lower(), val)
    return event


def base_url_of(resp: dict) -> str:
    return resp.get("url", "")


def _event_for(resp: dict) -> dict:
    return build_event(resp)


class MatcherError(ValueError):
    pass


def run_matchers(matchers: list[dict], condition: str, event: dict) -> tuple[bool, dict]:
    """Port of nuclei pkg/operators/operators.go Execute + pkg/operators/matchers/match.go.
    matchers-condition default OR (operators.go:52)."""
    is_and = (condition or "or").lower() == "and"
    matched_any = False
    matched_all = True
    detail: dict[str, list[str]] = {}
    for m in matchers:
        ok, ev = _run_one_matcher(m, event)
        neg = bool(m.get("negative"))
        ok = (not ok) if neg else ok
        matched_any = matched_any or ok
        matched_all = matched_all and ok
        if ok:
            detail[m.get("name") or m.get("type", "?")] = ev or []
    return (matched_all if is_and else matched_any), detail


def _run_one_matcher(m: dict, event: dict) -> tuple[bool, list[str]]:
    part = (m.get("part") or "body").lower()
    if part == "header":
        part = "all_headers"          # nuclei getMatchPart
    if part == "all":
        corpus = str(event.get("body", "")) + str(event.get("all_headers", ""))
    elif part == "response":
        corpus = str(event.get("response", ""))
    else:
        corpus = str(event.get(part if part in event else "body", ""))
    mtype = (m.get("type") or "").lower()
    if mtype == "status":
        ok = event["status_code"] in (m.get("status") or [])
        return ok, ([str(event["status_code"])] if ok else [])
    if mtype == "word":
        return _match_words(m, corpus)
    if mtype == "regex":
        return _match_regex(m, corpus)
    raise MatcherError(f"unsupported matcher type: {mtype} (subset: status/word/regex)")


def _match_words(m: dict, corpus: str) -> tuple[bool, list[str]]:
    cond = (m.get("condition") or "or").lower()
    words = list(m.get("words") or [])
    ci = bool(m.get("case-insensitive"))
    if ci:
        corpus = corpus.lower()
    hit: list[str] = []
    for w in words:
        ww = w.lower() if ci else w
        if ww in corpus:
            if cond == "or":
                return True, [ww]
            hit.append(ww)
        elif cond == "and":
            return False, []
    if cond == "and" and len(hit) == len(words) and words:
        return True, hit
    return (len(hit) > 0), hit


def _match_regex(m: dict, corpus: str) -> tuple[bool, list[str]]:
    cond = (m.get("condition") or "or").lower()
    flags = re.IGNORECASE if m.get("case-insensitive") else 0
    hit: list[str] = []
    for rx in m.get("regex") or []:
        found = re.findall(rx, corpus, flags) or []
        if found:
            if cond == "or":
                return True, found[:1]
            hit += [found[0] if isinstance(found[0], str) else str(found[0])]
        elif cond == "and":
            return False, []
    if cond == "and" and hit:
        return True, hit
    return (len(hit) > 0), hit


def run_extractors(extractors: list[dict], event: dict) -> list[str]:
    """Port of nuclei extractors (subset): regex w/ group, kval on the event
    map (lowercased keys), json dotted paths with [N] indices."""
    out: list[str] = []
    for e in extractors:
        etype = (e.get("type") or "").lower()
        part = (e.get("part") or "body").lower()
        if part == "header":
            part = "all_headers"
        if part == "all":
            corpus = str(event.get("body", "")) + str(event.get("all_headers", ""))
        else:
            corpus = str(event.get(part if part in event else "body", ""))
        if etype == "regex":
            group = int(e.get("group") or 0)
            for rx in e.get("regex") or []:
                # nuclei uses FindAllStringSubmatch: m.group(group) semantics
                for m in re.finditer(rx, corpus,
                                     re.IGNORECASE if e.get("case-insensitive") else 0):
                    try:
                        out.append(m.group(group))
                    except (IndexError, re.error):
                        continue
        elif etype == "kval":
            for k in e.get("kval") or []:
                v = event.get(k.lower().replace("-", "_"))
                if v is None:
                    v = event.get(k.lower())
                if v is not None:
                    out.append(str(v))
        elif etype == "json":
            try:
                doc = json.loads(corpus)
            except Exception:
                continue
            for path in e.get("json") or []:
                cur: Any = doc
                ok = True
                for token in re.findall(r"[^.\[\]]+|\[\d+\]", path):
                    if token.startswith("[") and token.endswith("]"):
                        idx = int(token[1:-1])
                        if isinstance(cur, list) and idx < len(cur):
                            cur = cur[idx]
                        else:
                            ok = False; break
                    else:
                        if isinstance(cur, dict) and token in cur:
                            cur = cur[token]
                        else:
                            ok = False; break
                if ok:
                    out.append(cur if isinstance(cur, str) else json.dumps(cur))
    return out


# --------------------------------------------------------------------------
# HTTP transports (live + demo fixture)
# --------------------------------------------------------------------------
@dataclass
class Transport:
    timeout: float = 8.0

    def get(self, url: str, headers: dict | None = None, redirects: bool = False,
            max_redirects: int = 5) -> dict | None:
        raise NotImplementedError


class LiveTransport(Transport):
    """httpx-backed transport. Only GET is emitted by template lane."""

    def get(self, url, headers=None, redirects=False, max_redirects=5):
        import httpx
        try:
            with httpx.Client(follow_redirects=redirects, timeout=self.timeout,
                              max_redirects=max_redirects) as client:
                r = client.get(url, headers=headers or {})
        except Exception:
            return None
        raw = "HTTP/1.1 " + str(r.status_code) + " " + r.reason_phrase + "\r\n"
        raw += "".join(f"{k}: {v}\r\n" for k, v in r.headers.items())
        raw += "\r\n" + r.text
        return {
            "url": str(r.url), "status": r.status_code, "raw": raw,
            "cookies": [f"{c.name}={c.value}" for c in r.cookies.jar],
            "request": f"GET {url}",
            "matched": str(r.url),
        }


class FixtureTransport(Transport):
    """DEMO_MODE transport: serves deterministic fixture responses."""

    def __init__(self, fixture: dict, timeout: float = 8.0):
        super().__init__(timeout)
        self.routes: list[tuple[str, dict]] = [
            (r["path"], r) for r in fixture.get("routes", [])
        ]
        self.routes.sort(key=lambda t: -len(t[0]))      # longest prefix first

    def get(self, url, headers=None, redirects=False, max_redirects=5):
        from urllib.parse import urlsplit
        path = urlsplit(url).path or "/"
        for prefix, route in self.routes:
            if path == prefix or path.startswith(prefix):
                return {
                    "url": url, "status": route.get("status", 200),
                    "raw": route["raw"], "cookies": route.get("cookies", []),
                    "request": f"GET {url}", "matched": url,
                }
        return None


# --------------------------------------------------------------------------
# Template lane runner (Nuclei-derived)
# --------------------------------------------------------------------------
class TemplateLane:
    def __init__(self, templates: list[dict]):
        self.templates = templates

    def scan(self, target_url: str, transport: Transport) -> list[dict]:
        findings: list[dict] = []
        for tpl in self.templates:
            blocks = tpl.get("http") or []
            all_matched, extracts, match_evidence = True, [], []
            for block in blocks:
                matched, block_extracts, detail = self._run_block(block, target_url, transport)
                if not matched:
                    all_matched = False
                    break
                extracts += block_extracts
                match_evidence += [v for vals in detail.values() for v in vals]
            if blocks and all_matched:
                findings.append(self._finding(tpl, target_url, extracts, match_evidence))
        return findings

    def _run_block(self, block: dict, target_url: str, transport: Transport):
        headers = {k: str(v) for k, v in (block.get("headers") or {}).items()}
        redirects = bool(block.get("redirects"))
        max_redirects = int(block.get("max-redirects") or 5)
        for raw_path in block.get("path") or []:
            url = _interpolate(str(raw_path), target_url)
            resp = transport.get(url, headers=headers, redirects=redirects,
                                 max_redirects=max_redirects)
            if resp is None:
                continue
            event = _event_for(resp)
            matchers = block.get("matchers") or []
            condition = block.get("matchers-condition") or "or"
            matched, detail = run_matchers(matchers, condition, event)
            extracts = run_extractors(block.get("extractors") or [], event)
            if matched:
                return True, extracts, detail
        return False, [], {}

    @staticmethod
    def _finding(tpl: dict, target_url: str, extracts: list[str], match_evidence: list[str]) -> dict:
        info = tpl.get("info") or {}
        classification = info.get("classification") or {}
        cve = classification.get("cve-id") or None
        cve = cve[0] if isinstance(cve, list) else cve
        cwe = classification.get("cwe-id") or None
        cwe = cwe[0] if isinstance(cwe, list) else cwe
        tid = tpl.get("id") or os.path.basename(tpl.get("_path", ""))
        ev = "; ".join(dict.fromkeys([e for e in extracts if e] + [e for e in match_evidence if e])) or None
        return {
            "cve_id": cve, "target_url": target_url,
            "severity": (info.get("severity") or "info").lower(),
            "source_tool": "nuclei-derived",
            "description": f"{info.get('name', tid)} [template {tid}]. "
                           f"Nuclei-style template match"
                           + (f"; extracted: {ev}" if ev else ""),
            "cwe": cwe, "evidence": ev or "template matched", "fix": None,
        }


# --------------------------------------------------------------------------
# Passive lane (ZAP-derived)
# --------------------------------------------------------------------------
ZAP_RISK = {"info": "info", "low": "low", "medium": "medium", "high": "high"}


@dataclass
class PassiveResponse:
    url: str
    method: str = "GET"
    status: int = 200
    headers: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""
    https: bool = True

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or [""])[0].lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    def header(self, name: str) -> str | None:
        vals = self.headers.get(name.lower())
        return vals[0] if vals else None

    def header_values(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


def _cookie_name(value: str) -> str:
    eq, semi = value.find("="), value.find(";")
    if eq == -1 or (semi != -1 and eq > semi):
        return ""
    return value[:eq].strip()


def _cookie_has_attr(value: str, attr: str) -> bool:
    """ZAP CookieUtils.hasAttribute: attributes are the ';'-split tail."""
    parts = value.split(";")
    if len(parts) == 1:
        return False
    return any(p.strip().lower() == attr for p in parts[1:])


def _cookie_expired(value: str) -> bool:
    """ZAP CookieUtils.isExpired: no expires attr -> not expired;
    unparseable or past date -> expired."""
    from email.utils import parsedate_to_datetime
    parts = value.split(";")
    expiry = next((p.split("=", 1)[1].strip() for p in parts[1:]
                   if p.strip().lower().startswith("expires=")), None)
    if expiry is None:
        return False
    try:
        when = parsedate_to_datetime(expiry)
    except Exception:
        return True                      # ZAP: null parse counts as expired
    from datetime import datetime, timezone
    return when.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)


def _cookie_attr_value(value: str, attr: str) -> str | None:
    """ZAP CookieUtils.getAttributeValue: value of 'attr=...' in the tail."""
    parts = value.split(";")
    for p in parts[1:]:
        k, _, v = p.partition("=")
        if k.strip().lower() == attr and v.strip():
            return v.strip()
    return None


# zap-extensions pscanrules zapHomeFiles/xml/debug-error-messages.txt (rule 10023)
_DEBUG_ERROR_PATTERNS = (
    "error occurred while processing request",
    "internal server error",
    "test page for apache",
    "failed to open stream: http request failed!",
    "parse error: parse error, unexpected t_variable",
    "the script whose uid is",
    "php parse error",
    "php warning",
    "php error",
    "warning: cannot modify header information - headers already sent",
    "mysqli error is",
    "mysql error is",
    "404 sc_not_found",
    "asp.net_sessionid",
    "servlet error:",
    "under construction",
    "welcome to windows 2000 internet services",
    "welcome to iis 4.0",
    "warning: supplied argument is not a valid file-handle resource",
    "warning: division by zero in",
    "warning: safe mode restriction in effect.",
    "error message : error loading required libraries.",
    "fatal error: call to undefined function",
    "access denied for user",
    "incorrect syntax near",
    "unclosed quotation mark before the character string",
    "there seems to have been a problem with the",
    "customerrors mode",
    "this error page might contain sensitive information because asp.net",
)

# zap-extensions pscanrules zapHomeFiles/xml/URL-information-disclosure-messages.txt
# (rule 10024) - param names matched case-insensitively with 'contains'
_URL_SENSITIVE_NAMES = (
    "user", "username", "pass", "password", "pwd", "token", "ticket",
    "session", "jsessionid", "sessionid",
)

# rule 10024 value patterns (copied from InformationDisclosureInUrlScanRule.java)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b")
_CREDIT_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}"
    r"|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b")
_US_SSN_RE = re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b")


def _zap_finding(rule: str, plugin_id: int, target: str, risk: str, cwe: int,
                  evidence: str, description: str) -> dict:
    return {
        "cve_id": None, "target_url": target,
        "severity": ZAP_RISK.get(risk, "info"),
        "source_tool": "zap-derived",
        "description": f"[{plugin_id}] {rule}: {description}",
        "cwe": f"CWE-{cwe}", "evidence": evidence, "fix": None,
    }


class PassiveLane:
    """Ports of zaproxy/zap-extensions pscanrules. Each rule keeps the Java
    trigger conditions, risk level and CWE id of its upstream rule."""

    def scan(self, resp: PassiveResponse) -> list[dict]:
        out: list[dict] = []
        out += self._server_header(resp)
        out += self._x_powered_by(resp)
        out += self._cookie_httponly(resp)
        out += self._cookie_secure(resp)
        out += self._hsts(resp)
        out += self._x_content_type_options(resp)
        out += self._csp_missing(resp)
        out += self._cache_control(resp)
        out += self._cors_wildcard(resp)
        out += self._debug_errors(resp)
        out += self._url_sensitive_info(resp)
        out += self._cookie_samesite(resp)
        out += self._x_frame_options(resp)
        return out

    def _server_header(self, r: PassiveResponse) -> list[dict]:
        # 10036 ServerHeaderInfoLeakScanRule: any digit in Server header value
        finds = []
        for directive in r.header_values("server"):
            if re.search(r"\d", directive):
                finds.append(_zap_finding(
                    "Server Header Info Leak", 10036, r.url, "low", 497, directive,
                    "The web/server header discloses a version number, giving attackers a "
                    "head start (ZAP rule 10036; OWASP A05:2021 Security Misconfiguration)."))
        return finds

    def _x_powered_by(self, r: PassiveResponse) -> list[dict]:
        # 10037 XPoweredByHeaderInfoLeakScanRule: header present at all
        vals = r.header_values("x-powered-by")
        if vals:
            return [_zap_finding("X-Powered-By Info Leak", 10037, r.url, "low", 497,
                                 ", ".join(vals),
                                 "X-Powered-By discloses technology information (ZAP rule 10037).")]
        return []

    def _cookie_httponly(self, r: PassiveResponse) -> list[dict]:
        # 10010 CookieHttpOnlyScanRule: Set-Cookie without HttpOnly, skipping expired cookies
        finds = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if not _cookie_has_attr(value, "httponly") and not _cookie_expired(value):
                finds.append(_zap_finding(
                    "Cookie No HttpOnly Flag", 10010, r.url, "low", 1004,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' set without the HttpOnly attribute "
                    "(ZAP rule 10010; CWE-1004)."))
        return finds

    def _cookie_secure(self, r: PassiveResponse) -> list[dict]:
        # 10011 CookieSecureFlagScanRule: only checked when request used SSL
        if not r.https:
            return []
        finds = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if not _cookie_has_attr(value, "secure") and not _cookie_expired(value):
                finds.append(_zap_finding(
                    "Cookie Without Secure Flag", 10011, r.url, "low", 614,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' set over HTTPS without the Secure "
                    "attribute (ZAP rule 10011; CWE-614)."))
        return finds

    def _hsts(self, r: PassiveResponse) -> list[dict]:
        # 10035 StrictTransportSecurityScanRule: HTTPS responses missing HSTS.
        # ZAP skips https redirects to the same host at thresholds above LOW.
        if not r.https:
            return []
        if r.header_values("strict-transport-security"):
            return []
        if r.status in (301, 302, 303, 307, 308):
            loc = r.header("location") or ""
            if not loc.startswith(("http://", "https://", "//")):
                return []          # relative redirect: ZAP skips
            if loc.lower().startswith("https://"):
                from urllib.parse import urlsplit
                req = urlsplit(r.url)
                dst = urlsplit(loc)
                if dst.netloc == req.netloc:
                    return []      # same-host https redirect: ZAP skips
        return [_zap_finding(
            "Strict-Transport-Security Missing", 10035, r.url, "low", 319,
            "(no Strict-Transport-Security header)",
            "HTTPS response does not set HSTS, allowing downgrade and cleartext "
            "interception on later visits (ZAP rule 10035; CWE-319).")]

    def _x_content_type_options(self, r: PassiveResponse) -> list[dict]:
        # 10021: body present, skip 4xx/5xx/redirects, header missing
        if len(r.body) == 0:
            return []
        if r.status >= 400 or r.status in (301, 302, 303, 307, 308):
            return []
        if r.header_values("x-content-type-options"):
            return []
        return [_zap_finding(
            "X-Content-Type-Options Missing", 10021, r.url, "low", 693,
            "(no X-Content-Type-Options header)",
            "Response lacks nosniff, allowing MIME-type confusion/sniffing attacks "
            "(ZAP rule 10021; CWE-693).")]

    def _csp_missing(self, r: PassiveResponse) -> list[dict]:
        # 10038: HTML non-redirect responses; no CSP header and no meta CSP
        if not r.is_html:
            return []
        if r.status in (301, 302, 303, 307, 308):
            return []
        if r.header_values("content-security-policy"):
            return []
        if re.search(r"http-equiv\s*=\s*[\"']?content-security-policy",
                     r.body, re.I):
            return []              # meta-tag CSP present
        return [_zap_finding(
            "Content-Security-Policy Missing", 10038, r.url, "medium", 693,
            "(no Content-Security-Policy header or meta policy)",
            "Response does not set a Content-Security-Policy, so injected script "
            "runs unrestricted (ZAP rule 10038; CWE-693).")]

    def _cache_control(self, r: PassiveResponse) -> list[dict]:
        # 10015 CacheControlScanRule: re-examine when the response does not
        # combine no-store, no-cache and must-revalidate.
        vals = r.header_values("cache-control")
        joined = "; ".join(vals).lower()
        if (not vals or "no-store" not in joined or "no-cache" not in joined
                or "must-revalidate" not in joined):
            return [_zap_finding(
                "Re-examine Cache Policy Directives", 10015, r.url, "info", 525,
                joined or "(no Cache-Control header)",
                "Cache-Control does not combine no-store, no-cache and "
                "must-revalidate, so sensitive content may be cached (ZAP rule 10015).")]
        return []

    def _cors_wildcard(self, r: PassiveResponse) -> list[dict]:
        # 10098 CrossDomainMisconfigurationScanRule: ACAO == "*"
        acao = r.header("access-control-allow-origin")
        if acao is not None and acao.strip() == "*":
            return [_zap_finding(
                "Cross-Domain Misconfiguration", 10098, r.url, "medium", 264,
                "Access-Control-Allow-Origin: *",
                "Wildcard CORS lets any origin read responses credentialed or not "
                "(ZAP rule 10098; CWE-264).")]
        return []

    def _debug_errors(self, r: PassiveResponse) -> list[dict]:
        # 10023 InformationDisclosureDebugErrorsScanRule: response body contains a
        # known debug/error string (case-insensitive substring; text responses only).
        # Risk LOW, CWE-1295, WASC-13.
        ct = r.content_type
        # ZAP HttpHeader.isText(): text/* plus common texty application types.
        if ct and not (ct.startswith("text/") or "json" in ct or "xml" in ct
                       or "javascript" in ct or "yaml" in ct):
            return []
        if len(r.body) == 0:
            return []
        low = r.body.lower()
        for pat in _DEBUG_ERROR_PATTERNS:
            if pat in low:
                start = low.index(pat)
                return [_zap_finding(
                    "Information Disclosure - Debug Error Messages", 10023, r.url,
                    "low", 1295, r.body[start:start + len(pat)],
                    "The response discloses a debug/error message that leaks stack "
                    "traces, SQL fragments or internal paths (ZAP rule 10023; "
                    "CWE-1295).")]
        return []

    def _url_sensitive_info(self, r: PassiveResponse) -> list[dict]:
        # 10024 InformationDisclosureInUrlScanRule: query parameter NAMES that
        # contain a sensitive word (case-insensitive 'contains'), and parameter
        # VALUES that look like emails / credit cards / US SSNs.
        # Risk INFO, CWE-598, WASC-13.
        from urllib.parse import urlsplit, parse_qsl
        query = urlsplit(r.url).query
        if not query:
            return []
        finds: list[dict] = []
        for name, value in parse_qsl(query, keep_blank_values=True):
            n = name.lower()
            for s in _URL_SENSITIVE_NAMES:
                if s in n:
                    finds.append(_zap_finding(
                        "Information Disclosure - Sensitive Information in URL",
                        10024, r.url, "info", 598, f"{name}={value}",
                        f"Query parameter '{name}' carries sensitive information "
                        f"(matched upstream token '{s}'); URLs leak into logs, "
                        "Referer headers and browser history (ZAP rule 10024; "
                        "CWE-598)."))
                    break
            if _EMAIL_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - Email Address in URL", 10024, r.url,
                    "info", 598, f"{name}={value}",
                    f"Value of parameter '{name}' looks like an email address "
                    "(ZAP rule 10024; CWE-598)."))
            if _CREDIT_CARD_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - Credit Card in URL", 10024, r.url,
                    "info", 598, f"{name}=*redacted*",
                    f"Value of parameter '{name}' matches a credit card pattern "
                    "(ZAP rule 10024; CWE-598)."))
            if _US_SSN_RE.search(value):
                finds.append(_zap_finding(
                    "Information Disclosure - US SSN in URL", 10024, r.url,
                    "info", 598, f"{name}=*redacted*",
                    f"Value of parameter '{name}' matches a US Social Security "
                    "Number pattern (ZAP rule 10024; CWE-598)."))
        return finds

    def _cookie_samesite(self, r: PassiveResponse) -> list[dict]:
        # 10054 CookieSameSiteScanRule (skip expired cookies):
        #   -1 SameSite attribute missing       Risk LOW, CWE-1275, WASC-13
        #   -2 SameSite=None (not at HIGH threshold)
        #   -3 SameSite with an illegal value
        finds: list[dict] = []
        for value in r.header_values("set-cookie") + r.header_values("set-cookie2"):
            if _cookie_expired(value):
                continue
            ss = _cookie_attr_value(value, "samesite")
            if ss is None:
                finds.append(_zap_finding(
                    "Cookie without SameSite Attribute", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' has no SameSite attribute, so "
                    "it is sent on cross-site requests and is exposed to CSRF "
                    "(ZAP rule 10054-1; CWE-1275)."))
            elif ss.lower() == "none":
                finds.append(_zap_finding(
                    "Cookie with SameSite None", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' uses SameSite=None, sending it "
                    "on every cross-site request (ZAP rule 10054-2; CWE-1275)."))
            elif ss.lower() not in ("strict", "lax", "none"):
                finds.append(_zap_finding(
                    "Cookie with Invalid SameSite Value", 10054, r.url, "low", 1275,
                    value.split(";")[0],
                    f"Cookie '{_cookie_name(value)}' has an unrecognised SameSite "
                    f"value '{ss}', which browsers treat as unset (ZAP rule "
                    "10054-3; CWE-1275)."))
        return finds

    def _x_frame_options(self, r: PassiveResponse) -> list[dict]:
        # 10020 AntiClickjackingScanRule at ZAP's default (MEDIUM) threshold:
        # HTML, non-empty text body, not an error/redirect. CSP frame-ancestors
        # takes precedence (no alert when present). XFO missing -> alert; XFO
        # value without deny/sameorigin -> malformed; duplicate XFO headers ->
        # multiple-headers alert. Risk MEDIUM, CWE-1021, WASC-15.
        if not r.is_html or len(r.body) == 0:
            return []
        if r.status >= 400 or r.status in (301, 302, 303, 307, 308):
            return []
        csp_vals = r.header_values("content-security-policy")
        if any("frame-ancestors" in c for c in csp_vals):
            return []                # ZAP: CSP frame-ancestors takes precedence
        finds: list[dict] = []
        xfo = r.header_values("x-frame-options")
        if not xfo:
            finds.append(_zap_finding(
                "Anti-clickjacking X-Frame-Options header missing", 10020, r.url,
                "medium", 1021, "(no X-Frame-Options header)",
                "The response does not set X-Frame-Options (or a CSP "
                "frame-ancestors policy), so the page can be embedded in a frame "
                "and used in clickjacking attacks (ZAP rule 10020-1; CWE-1021)."))
        else:
            for v in xfo:
                lv = v.lower()
                if "deny" not in lv and "sameorigin" not in lv:
                    finds.append(_zap_finding(
                        "X-Frame-Options Setting Malformed", 10020, r.url, "medium",
                        1021, v,
                        f"X-Frame-Options value '{v}' is not DENY or SAMEORIGIN "
                        "and will be ignored by browsers (ZAP rule 10020-4; "
                        "CWE-1021)."))
            if len(xfo) > 1:
                finds.append(_zap_finding(
                    "Multiple X-Frame-Options Header Entries", 10020, r.url,
                    "medium", 1021, "; ".join(xfo),
                    "Multiple X-Frame-Options headers are present; browsers apply "
                    "only one, which may not be the secure one (ZAP rule 10020-2; "
                    "CWE-1021)."))
        return finds


# --------------------------------------------------------------------------
# Repo acquisition (GitHub codeload tarball / local walk)
# --------------------------------------------------------------------------
_SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}


def github_repo_files(repo_url: str, max_files: int = 400) -> dict[str, str]:
    """Download HEAD tarball of owner/repo and return {relpath: text} for the
    manifests TRIAD scans (trivy-style: manifests anywhere in the tree)."""
    from urllib.parse import urlsplit
    parts = urlsplit(repo_url).path.strip("/").split("/")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    tar_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
    req = urllib.request.Request(tar_url, headers={"User-Agent": "TRIAD-Scanner/1.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        blob = resp.read()
    files: dict[str, str] = {}
    with tarfile.open(fileobj=BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size > 1_000_000:
                continue
            name = os.path.basename(member.name)
            if name not in MANIFEST_PARSERS:
                continue
            rel = "/".join(member.name.split("/")[1:]) or member.name
            if any(seg in _SKIP_DIRS for seg in rel.split("/")):
                continue
            files[rel] = tar.extractfile(member).read().decode("utf-8", "replace")
            if len(files) >= max_files:
                break
    return files


def local_repo_files(root: str, max_files: int = 400) -> dict[str, str]:
    files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if fname not in MANIFEST_PARSERS:
                continue
            path = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(path) > 1_000_000:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    files[os.path.relpath(path, root)] = fh.read()
            except OSError:
                continue
            if len(files) >= max_files:
                return files
    return files


def response_to_passive(resp: dict) -> PassiveResponse:
    """Adapt a Transport response dict to the PassiveLane input."""
    header_blob, _, body = resp["raw"].partition("\r\n\r\n")
    headers: dict[str, list[str]] = {}
    for line in header_blob.split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    return PassiveResponse(
        url=resp["url"], method="GET", status=resp["status"], headers=headers,
        body=body, https=resp["url"].lower().startswith("https://"),
    )


# --------------------------------------------------------------------------
# TRIAD_Scanner
# --------------------------------------------------------------------------
class TRIAD_Scanner:
    """Single-input scanner: GitHub repo URL OR live website URL (or local dir).

    GitHub repo -> Trivy-derived dependency lane.
    Live URL    -> Nuclei-derived template lane, then ZAP-derived passive lane.

    DEMO_MODE mocks the TARGET (fixtures), never the ENGINE: the same matching
    code runs, instantly, with zero network.
    """

    def __init__(self, templates_dir: str = DEFAULT_TEMPLATES,
                 index_path: str = DEFAULT_INDEX, demo_dir: str = DEFAULT_DEMO_DIR,
                 timeout: float = 8.0):
        self.deps = DependencyLane(index_path)
        self.templates = load_templates(templates_dir)
        self.template_lane = TemplateLane(self.templates)
        self.passive_lane = PassiveLane()
        self.demo_dir = demo_dir
        self.timeout = timeout

    # -- public API ---------------------------------------------------------
    def scan(self, target: str, demo: bool | None = None) -> dict:
        demo = (os.environ.get("TRIAD_DEMO_MODE", "0") == "1") if demo is None else demo
        started = time.time()
        kind, normalized = classify_target(target)
        findings: list[dict] = []
        routed_as = kind
        if kind in ("invalid",):
            return self._report(target, routed_as, demo, started, [
                {"cve_id": None, "target_url": target, "severity": "info",
                 "source_tool": "triad-router", "description":
                 f"Input could not be routed (got: {target!r}). Expected a GitHub "
                 "repo URL, an http(s) URL, or an existing directory path.",
                 "cwe": None, "evidence": None, "fix": None}])
        if kind in ("github", "local"):
            routed_as = f"{kind}:trivy-dependencies"
            findings = self._scan_dependencies(normalized, demo)
        elif kind == "web":
            routed_as = "web:nuclei-templates+zap-passive"
            findings = self._scan_web(normalized, demo)
        return self._report(normalized, routed_as, demo, started, findings)

    def to_json(self, target: str, demo: bool | None = None, indent: int | None = 2) -> str:
        return json.dumps(self.scan(target, demo=demo)["findings"], indent=indent)

    # -- lanes --------------------------------------------------------------
    def _scan_dependencies(self, target: str, demo: bool) -> list[dict]:
        if demo:
            files = local_repo_files(self.demo_dir)
            files = {k: v for k, v in files.items() if not k.startswith("web_")}
        elif target.startswith("https://github.com/") or target.startswith("http://github.com/"):
            try:
                files = github_repo_files(target)
            except Exception as exc:                     # network / rate-limit / private
                return [{
                    "cve_id": None, "target_url": target, "severity": "info",
                    "source_tool": "triad-derived",
                    "description":
                        "GitHub fetch failed (" + type(exc).__name__ +
                        "). Public repos only: the tarball endpoint must be "
                        "reachable and the repo must not be private.",
                    "cwe": None, "evidence": str(exc)[:200], "fix": None}]
        else:
            files = local_repo_files(target)
        if not files:
            return [{
                "cve_id": None, "target_url": target, "severity": "info",
                "source_tool": "triad-derived",
                "description": "No dependency manifests (package.json, "
                               "requirements.txt, pyproject.toml) found.",
                "cwe": None, "evidence": None, "fix": None}]
        findings = self.deps.scan_manifests(files, target)
        if not findings:
            manifests = ", ".join(sorted(files)[:3]) + (" ..." if len(files) > 3 else "")
            return [{
                "cve_id": None, "target_url": target, "severity": "info",
                "source_tool": "triad-derived",
                "description":
                    f"Clean scan: {len(files)} manifest(s) parsed ({manifests}) "
                    "- no declared version matches any advisory in the index.",
                "cwe": None, "evidence": None, "fix": None}]
        return findings

    def _scan_web(self, target: str, demo: bool) -> list[dict]:
        base = target if target.count("/") > 3 else target.rstrip("/") + "/"
        if demo:
            with open(os.path.join(self.demo_dir, "web_fixture.json"), encoding="utf-8") as fh:
                fixture = json.load(fh)
            transport: Transport = FixtureTransport(fixture)
        else:
            transport = LiveTransport(timeout=self.timeout)
        findings = []
        findings += self.template_lane.scan(base, transport)
        root = transport.get(base)
        if root is not None:
            findings += self.passive_lane.scan(response_to_passive(root))
        if not findings:
            if not demo and root is None:
                return [{
                    "cve_id": None, "target_url": base, "severity": "info",
                    "source_tool": "triad-router",
                    "description":
                        f"Target unreachable: GET {base} produced no response "
                        "(DNS failure, connection refused, or timeout). Verify "
                        "the URL and that the host is reachable.",
                    "cwe": None, "evidence": None, "fix": None}]
            return [{
                "cve_id": None, "target_url": base, "severity": "info",
                "source_tool": "triad-router",
                "description": "Target reachable but no template matched and no "
                               "passive rule fired.",
                "cwe": None, "evidence": None, "fix": None}]
        return findings

    # -- report -------------------------------------------------------------
    @staticmethod
    def _report(target: str, routed_as: str, demo: bool, started: float,
                findings: list[dict]) -> dict:
        findings.sort(key=lambda f: (f.get("severity") != "critical",
                                     f.get("severity") != "high",
                                     f.get("severity") != "medium",
                                     f.get("severity") != "low",
                                     f.get("cve_id") or ""))
        return {
            "target": target,
            "routed_as": routed_as,
            "demo_mode": demo,
            "scan_id": f"triad-{int(started * 1000):013x}",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
            "duration_ms": int((time.time() - started) * 1000),
            "finding_count": len(findings),
            "findings": findings,
        }


__all__ = [
    "TRIAD_Scanner", "classify_target", "DependencyLane", "TemplateLane",
    "PassiveLane", "LiveTransport", "FixtureTransport", "load_templates",
    "is_vulnerable", "matches_constraints", "PassiveResponse",
]
