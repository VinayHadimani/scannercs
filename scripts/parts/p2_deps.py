

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
