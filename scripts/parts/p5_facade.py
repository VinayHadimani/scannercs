

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
            files = github_repo_files(target)
        else:
            files = local_repo_files(target)
        if not files:
            return [{
                "cve_id": None, "target_url": target, "severity": "info",
                "source_tool": "triad-derived",
                "description": "No dependency manifests (package.json, "
                               "requirements.txt, pyproject.toml) found.",
                "cwe": None, "evidence": None, "fix": None}]
        return self.deps.scan_manifests(files, target)

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
