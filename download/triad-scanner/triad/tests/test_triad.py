"""TRIAD_Scanner test suite: routing, version engine, manifest parsers,
dependency lane (real OSV-derived index), nuclei-style matchers/extractors,
ZAP passive rules, template lane, demo mode, live fixture server, FastAPI."""
import json
import os
import sys

import pytest

PKG = os.path.dirname(os.path.abspath(__file__)) + "/.."
sys.path.insert(0, PKG)
sys.path.insert(0, os.path.join(PKG, "tests"))

from triad_scanner import (  # noqa: E402
    TRIAD_Scanner, DependencyLane, TemplateLane, PassiveLane, PassiveResponse,
    FixtureTransport, load_templates, run_matchers, run_extractors,
    build_event, is_vulnerable, matches_constraints, classify_target,
    parse_package_json, parse_requirements_txt, parse_pyproject_toml,
    response_to_passive, github_repo_files, local_repo_files,
)
from fixture_server import start_server  # noqa: E402


# ------------------------------------------------------------------ routing
def test_routing():
    assert classify_target("https://github.com/expressjs/express")[0] == "github"
    assert classify_target("http://github.com/a/b.git")[1] == "https://github.com/a/b"
    assert classify_target("https://example.com/x")[0] == "web"
    assert classify_target("example.com")[0] == "web"
    assert classify_target("example.com:8080/x")[1] == "https://example.com:8080/x"
    assert classify_target(PKG)[0] == "local"
    assert classify_target("")[0] == "invalid"
    assert classify_target("::::nope")[0] == "invalid"


# ----------------------------------------------------- version engine
@pytest.mark.parametrize("version,constraints,expected", [
    ("2.0.0", ">= 1.0.0, < 2.5.0", True),
    ("2.5.0", ">= 1.0.0, < 2.5.0", False),          # fixed boundary exclusive
    ("1.9.9", ">= 1.0.0, < 2.5.0", True),
    ("3.0.0", ">= 1.0.0, < 2.5.0", False),
    ("3.0.0", ">= 1.0.0, < 2.5.0 || >= 3.0.0, < 3.1.0", True),   # OR groups
    ("2.7.0", ">= 1.0.0, < 2.5.0 || >= 3.0.0, < 3.1.0", False),
    ("2.0.0", ">= 2.0.0", True),
    ("1.9.9", ">= 2.0.0", False),
    ("1.0.0", "<= 1.0.0", True),                    # last_affected inclusive
    ("1.0.1", "<= 1.0.0", False),
    ("1.2.3", "1.2.3", True),                       # bare pin
    ("1.2.4", "1.2.3", False),
])
def test_matches_constraints_semver(version, constraints, expected):
    assert matches_constraints(version, constraints, "semver") is expected


@pytest.mark.parametrize("version,constraints,expected", [
    ("1.26.3", ">= 1.25.0, < 1.26.8", True),
    ("1.26.8", ">= 1.25.0, < 1.26.8", False),
    ("2.0.0", ">= 1.26, < 2.0", False),             # pep440 2-tuple handling
    ("1.26", ">= 1.26, < 2.0", True),
    ("1.0rc1", ">= 1.0, < 2.0", False),             # pep440: rc sorts before final
    ("1.0", ">= 1.0rc1", True),                      # final > rc
])
def test_matches_constraints_pep440(version, constraints, expected):
    assert matches_constraints(version, constraints, "pep440") is expected


def test_is_vulnerable_fail_open():
    # trivy compare.go: no range info -> treat as affected
    assert is_vulnerable("1.0.0", [], None, "semver") is True
    assert is_vulnerable("1.0.0", None, None, "semver") is True


def test_is_vulnerable_patched_exclusion():
    ranges = [">= 1.0.0, < 2.0.0"]
    assert is_vulnerable("1.5.0", ranges, ["1.5.0"], "semver") is False
    assert is_vulnerable("1.5.1", ranges, ["1.5.0"], "semver") is True


# --------------------------------------------------------- manifest parsers
def test_parse_package_json():
    doc = {
        "name": "x",
        "dependencies": {"express": "4.18.1", "lodash": "^4.17.20", "bad": "*"},
        "devDependencies": {"underscore": "~1.12.0"},
        "optionalDependencies": {"qs": ">=6.10.1 <6.10.3"},
    }
    deps = parse_package_json(json.dumps(doc))
    assert ("express", "4.18.1", "npm") in deps
    assert ("lodash", "4.17.20", "npm") in deps          # lower bound approx
    assert ("underscore", "1.12.0", "npm") in deps
    assert ("qs", "6.10.1", "npm") in deps
    assert all(n != "bad" for n, _, _ in deps)


def test_parse_requirements_txt():
    text = ("# core deps\n"
            "requests==2.25.1\n"
            "urllib3>=1.26.0,<1.27\n"
            "Pillow[docs]==8.1.0  # pinned for demo\n"
            "Django >= 3.2, < 4.0\n"
            "-r other.txt\n"
            "celery==5.0.5; python_version >= '3.6'\n")
    deps = parse_requirements_txt(text)
    assert ("requests", "2.25.1", "pip") in deps
    assert ("urllib3", "1.26.0", "pip") in deps
    assert ("Pillow", "8.1.0", "pip") in deps
    assert ("Django", "3.2", "pip") in deps
    assert ("celery", "5.0.5", "pip") in deps
    assert all(n != "-r" for n, _, _ in deps)


def test_parse_pyproject_toml():
    text = (
        "[project]\n"
        'dependencies = ["requests==2.25.1", "urllib3>=1.26.0"]\n'
        "\n"
        "[project.optional-dependencies]\n"
        'dev = ["pytest==8.0.0"]\n'
    )
    deps = parse_pyproject_toml(text)
    assert ("requests", "2.25.1", "pip") in deps
    assert ("urllib3", "1.26.0", "pip") in deps
    assert ("pytest", "8.0.0", "pip") in deps


# --------------------------------------------------- dependency lane
def test_dependency_lane_real_index():
    lane = DependencyLane()
    files = {"package.json": json.dumps({"dependencies": {"express": "4.18.1"}})}
    finds = lane.scan_manifests(files, "https://github.com/x/y")
    cves = {f["cve_id"] for f in finds}
    assert "CVE-2024-29041" in cves                    # express path-to-regexp
    assert "CVE-2024-43796" in cves                    # express res.redirect
    for f in finds:
        assert f["source_tool"] == "triad-derived"
        assert f["target_url"].startswith("https://github.com/x/y/package.json")
        assert f["severity"] in ("info", "low", "medium", "high", "critical")
        assert "express 4.18.1" in f["description"]


def test_dependency_lane_fixed_version_clean():
    lane = DependencyLane()
    files = {"package.json": json.dumps({"dependencies": {"express": "4.21.2"}})}
    finds = [f for f in lane.scan_manifests(files, "https://github.com/x/y")
             if f["cve_id"] in ("CVE-2024-29041", "CVE-2024-43796")]
    assert finds == []                                  # fixed version: no hit


# ------------------------------------------------- nuclei matchers/extractors
def _event(raw, status=200):
    return build_event({"raw": raw, "status": status, "url": "https://t/",
                        "cookies": [], "request": "", "matched": "https://t/"})


def test_matchers_default_or_condition():
    ev = _event("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\nhello")
    ok, _ = run_matchers(
        [{"type": "word", "words": ["absent"]},
         {"type": "word", "words": ["hello"]}], "or", ev)
    assert ok is True                    # default OR: second matcher hit


def test_matchers_and_condition_requires_all():
    ev = _event("HTTP/1.1 200 OK\r\n\r\nhello world")
    ok, _ = run_matchers(
        [{"type": "word", "words": ["hello"]},
         {"type": "word", "words": ["absent"]}], "and", ev)
    assert ok is False


def test_matchers_negative():
    ev = _event("HTTP/1.1 200 OK\r\n\r\nhello")
    ok, _ = run_matchers(
        [{"type": "word", "words": ["absent"], "negative": True}], "and", ev)
    assert ok is True


def test_matchers_case_insensitive_and_parts():
    raw = "HTTP/1.1 200 OK\r\nX-Powered-By: PHP/7.4.3\r\n\r\nBODY"
    ev = _event(raw)
    ok, _ = run_matchers(
        [{"type": "word", "part": "header", "words": ["php"],
          "case-insensitive": True},
         {"type": "word", "part": "body", "words": ["body"],
          "case-insensitive": True}], "and", ev)
    assert ok is True                    # header + body parts both matched


def test_extractors():
    ev = _event("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n"
                "root:x:0:0:root:/root:/bin/bash\nrunning Apache/2.4.49 here")
    out = run_extractors([{"type": "kval", "kval": ["server"]}], ev)
    assert "Apache/2.4.49" in out
    out = run_extractors([{"type": "regex", "regex": [r"(2\.4\.\d+)"], "group": 1}], ev)
    assert "2.4.49" in out


def test_extractors_json():
    ev = _event('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
               '{"_links": {"env": {"href": "http://t/actuator/env"}}}')
    out = run_extractors([{"type": "json", "json": ["_links.env.href"]}], ev)
    assert "http://t/actuator/env" in out


# ------------------------------------------------------------- ZAP rules
def _zap_resp(**over):
    base = dict(url="https://demo.triad.local/", method="GET", status=200,
                headers={
                    "server": ["Apache/2.4.49 (Unix)"],
                    "x-powered-by": ["PHP/7.4.3"],
                    "set-cookie": ["session=abc123; Path=/"],
                    "access-control-allow-origin": ["*"],
                    "content-type": ["text/html; charset=UTF-8"],
                },
                body="<html><h1>Index of /</h1></html>", https=True)
    base.update(over)
    return PassiveResponse(**base)


def test_zap_rules_fire_on_misconfigured_target():
    lane = PassiveLane()
    findings = lane.scan(_zap_resp())
    by_cwe = {f["cwe"] for f in findings}
    assert "CWE-497" in by_cwe      # server + x-powered-by leaks
    assert "CWE-1004" in by_cwe     # cookie httponly
    assert "CWE-614" in by_cwe      # cookie secure (https)
    assert "CWE-319" in by_cwe      # HSTS missing
    assert "CWE-693" in by_cwe      # XCTO + CSP missing
    assert "CWE-264" in by_cwe      # CORS wildcard
    assert all(f["cve_id"] is None for f in findings)   # passive alerts are CWE-based
    for f in findings:
        for key in ("cve_id", "target_url", "severity", "source_tool", "description"):
            assert key in f
        for key in ("target_url", "severity", "source_tool", "description"):
            assert f[key] is not None


def test_zap_rules_clean_target():
    lane = PassiveLane()
    resp = _zap_resp(headers={
        "server": ["Apache"],
        "strict-transport-security": ["max-age=63072000"],
        "x-content-type-options": ["nosniff"],
        "content-security-policy": ["default-src 'self'"],
        "cache-control": ["no-store, no-cache, must-revalidate"],
        "content-type": ["text/html"],
        "set-cookie": ["session=abc; HttpOnly; Secure; SameSite=Lax"],
        "x-frame-options": ["DENY"],
    })
    findings = lane.scan(resp)
    assert findings == []


def test_zap_hsts_https_only_and_redirect_nuance():
    lane = PassiveLane()
    http_resp = _zap_resp(https=False)
    assert all(f["cwe"] != "CWE-319" for f in lane.scan(http_resp))
    redir = _zap_resp(status=302, headers={
        "server": ["Apache"], "location": ["/login"],
        "content-type": ["text/html"]})
    assert all(f["cwe"] != "CWE-319" for f in lane.scan(redir))   # relative redirect skipped


def test_zap_cache_control_requires_directives():
    lane = PassiveLane()
    partial = _zap_resp(headers={
        "server": ["Apache"], "content-type": ["text/html"],
        "cache-control": ["no-store"]})     # missing no-cache + must-revalidate
    assert any(f["cwe"] == "CWE-525" for f in lane.scan(partial))


def test_zap_debug_errors_10023():
    lane = PassiveLane()
    resp = _zap_resp(
        body="<html>Warning: Division by zero in /var/www/app.php on line 3</html>")
    finds = [f for f in lane.scan(resp) if f["cwe"] == "CWE-1295"]
    assert len(finds) == 1
    assert "Division by zero" in finds[0]["evidence"]
    # non-text responses are skipped (ZAP isText())
    binary = _zap_resp(headers={"server": ["Apache"],
                                "content-type": ["image/png"]},
                       body="Warning: Division by zero in")
    assert all(f["cwe"] != "CWE-1295" for f in lane.scan(binary))


def test_zap_url_sensitive_info_10024():
    lane = PassiveLane()
    resp = _zap_resp(
        url="https://demo.triad.local/login?username=admin&mail=admin%40corp.com&ssn=123-45-6789")
    finds = [f for f in lane.scan(resp) if f["cwe"] == "CWE-598"]
    assert len(finds) == 3            # sensitive name + email value + SSN value
    assert all(f["severity"] == "info" for f in finds)
    clean = _zap_resp(url="https://demo.triad.local/page?id=42&lang=en")
    assert all(f["cwe"] != "CWE-598" for f in lane.scan(clean))


def test_zap_cookie_samesite_10054():
    lane = PassiveLane()
    resp = _zap_resp(headers={
        "server": ["Apache"], "content-type": ["text/html"],
        "set-cookie": ["a=1; Path=/",
                       "b=1; Path=/; SameSite=None",
                       "c=1; Path=/; SameSite=SOMETIMES",
                       "d=1; Path=/; SameSite=Lax"]})
    finds = [f for f in lane.scan(resp) if "10054" in f["description"]]
    assert len(finds) == 3            # missing + None + bad value; 'd' is clean
    assert all(f["cwe"] == "CWE-1275" for f in finds)


def test_zap_xfo_10020():
    lane = PassiveLane()
    # missing X-Frame-Options -> alert
    assert any(f["cwe"] == "CWE-1021" for f in lane.scan(_zap_resp()))
    # CSP frame-ancestors takes precedence -> no alert
    csp = _zap_resp(headers={"server": ["Apache"],
                             "content-type": ["text/html"],
                             "content-security-policy": ["frame-ancestors 'none'"]})
    assert all(f["cwe"] != "CWE-1021" for f in lane.scan(csp))
    # malformed value -> alert
    bad = _zap_resp(headers={"server": ["Apache"],
                             "content-type": ["text/html"],
                             "x-frame-options": ["ALLOW-FROM https://x.example"]})
    assert any(f["cwe"] == "CWE-1021" and "Malformed" in f["description"]
               for f in lane.scan(bad))
    # proper DENY -> clean
    good = _zap_resp(headers={"server": ["Apache"],
                              "content-type": ["text/html"],
                              "x-frame-options": ["DENY"]})
    assert all(f["cwe"] != "CWE-1021" for f in lane.scan(good))


# --------------------------------------------------- template lane + demo
def test_template_lane_demo_fixture():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    assert len(tpl) == 12
    fixture = json.load(open(os.path.join(PKG, "data/demo/web_fixture.json")))
    findings = TemplateLane(tpl).scan("https://demo.triad.local/",
                                      FixtureTransport(fixture))
    by_cve = {f["cve_id"] for f in findings}
    assert "CVE-2021-41773" in by_cve                     # path traversal matched
    assert any("Apache/2.4.49" in (f["evidence"] or "") for f in findings)  # tech extract


def test_new_templates_fire_on_demo_fixture():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    fixture = json.load(open(os.path.join(PKG, "data/demo/web_fixture.json")))
    findings = TemplateLane(tpl).scan("https://demo.triad.local/",
                                      FixtureTransport(fixture))
    descs = " | ".join(f["description"] for f in findings)
    for marker in (".env file exposure", ".git config file exposure",
                   "Spring Boot Actuator exposed", "phpinfo() page exposure",
                   "CORS misconfiguration", "Tomcat manager application exposed",
                   "Jenkins instance detected", "Swagger UI exposed"):
        assert marker in descs, f"template did not fire: {marker}"
    ev = " | ".join((f["evidence"] or "") for f in findings)
    assert "APP_KEY=" in ev                                   # .env regex extractor
    assert "repositoryformatversion = 0" in ev                # git config extractor
    assert "/actuator/env" in ev                              # json extractor
    assert "PHP Version 7.4.3" in ev                          # phpinfo extractor
    assert "Apache Tomcat/9.0.65" in ev                       # tomcat extractor
    assert all(f["severity"] in ("info", "low", "medium", "high", "critical")
               for f in findings)


def test_templates_no_false_positive_on_clean_site():
    tpl = load_templates(os.path.join(PKG, "triad_templates"))
    clean_fixture = {"routes": [{
        "path": "/", "status": 200,
        "raw": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
               "<html><head><title>Home</title></head><body>Hello world</body></html>",
    }]}
    findings = TemplateLane(tpl).scan("https://clean.triad.local/",
                                      FixtureTransport(clean_fixture))
    findings = [f for f in findings if f["severity"] != "info"]
    assert findings == []      # only info-severity tech fingerprints allowed


def test_demo_mode_instant_and_offline():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://demo.triad.local", demo=True)
    assert report["demo_mode"] is True
    assert report["duration_ms"] < 500
    cves = {f["cve_id"] for f in report["findings"]}
    assert "CVE-2021-41773" in cves
    repo = scanner.scan("https://github.com/triad/demo-app", demo=True)
    repo_cves = {f["cve_id"] for f in repo["findings"]}
    assert "CVE-2020-28500" in repo_cves          # lodash 4.17.20
    assert "CVE-2023-32681" in repo_cves          # requests 2.25.1
    assert "CVE-2024-29041" in repo_cves          # express 4.18.1


def test_demo_mode_new_detections_end_to_end():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://demo.triad.local", demo=True)
    assert report["duration_ms"] < 500
    cwes = {f["cwe"] for f in report["findings"]}
    assert "CWE-1295" in cwes       # ZAP 10023 debug error in fixture body
    assert "CWE-1021" in cwes       # ZAP 10020 X-Frame-Options missing
    assert "CWE-1275" in cwes       # ZAP 10054 SameSite missing
    descs = " | ".join(f["description"] for f in report["findings"])
    assert "Spring Boot Actuator exposed" in descs
    assert ".env file exposure" in descs
    tools = {f["source_tool"] for f in report["findings"]}
    assert {"nuclei-derived", "zap-derived"} <= tools


def test_demo_mode_repo_report_shape():
    scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
    report = scanner.scan("https://github.com/triad/demo-app", demo=True)
    for f in report["findings"]:
        assert set(("cve_id", "target_url", "severity", "source_tool",
                    "description")) <= set(f)
    assert report["routed_as"] == "github:trivy-dependencies"


# ------------------------------------------------------- LIVE end-to-end
def test_live_scan_against_fixture_server():
    server, url = start_server()
    try:
        scanner = TRIAD_Scanner(demo_dir=os.path.join(PKG, "data/demo"))
        report = scanner.scan(url, demo=False)
        assert report["demo_mode"] is False
        cves = {f["cve_id"] for f in report["findings"]}
        cwes = {f["cwe"] for f in report["findings"]}
        assert "CVE-2021-41773" in cves
        assert "CWE-497" in cwes
        assert "CWE-1004" in cwes
        assert "CWE-264" in cwes
        tools = {f["source_tool"] for f in report["findings"]}
        assert "nuclei-derived" in tools and "zap-derived" in tools
    finally:
        server.shutdown()


# ------------------------------------------------------------- FastAPI
def test_fastapi_scan_route():
    from fastapi.testclient import TestClient
    import server as srv
    client = TestClient(srv.app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["demo_mode"] is True or body["demo_mode"] is False

    r = client.post("/scan", json={"target": "https://demo.triad.local"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["finding_count"] > 0
    cves = {f["cve_id"] for f in doc["findings"]}
    assert "CVE-2021-41773" in cves

    server_, url = start_server()
    try:
        r = client.post("/scan", json={"target": url, "demo": False})
        assert r.status_code == 200
        assert r.json()["demo_mode"] is False
        assert {f["cve_id"] for f in r.json()["findings"]} >= {"CVE-2021-41773"}
    finally:
        server_.shutdown()


def test_fastapi_invalid_target():
    from fastapi.testclient import TestClient
    import server as srv
    client = TestClient(srv.app)
    r = client.post("/scan", json={"target": "::::not-a-target"})
    assert r.status_code == 200
    doc = r.json()
    assert doc["routed_as"] == "invalid"
    assert doc["findings"][0]["severity"] == "info"


# -------------------------------------------------- routing + console + cli
def test_classify_bare_github():
    assert classify_target("github.com/expressjs/express")[0] == "github"
    assert classify_target("github.com/a/b.git")[1] == "https://github.com/a/b"
    assert classify_target("www.GitHub.com/a/b/tree/main")[1] == "https://github.com/a/b"
    assert classify_target("github.com/expressjs")[0] == "web"          # org only
    assert classify_target("example.com")[0] == "web"                    # unchanged


def test_clean_scan_info_finding(tmp_path):
    import triad_scanner as ts
    # "left-pad" is not in the advisory index -> guaranteed zero matches
    (tmp_path / "package.json").write_text(
        '{"name": "cleanapp", "dependencies": {"left-pad": "1.3.0"}}',
        encoding="utf-8")
    scanner = ts.TRIAD_Scanner()
    doc = scanner.scan(str(tmp_path), demo=False)
    assert doc["routed_as"] == "local:trivy-dependencies"
    assert doc["finding_count"] == 1
    f = doc["findings"][0]
    assert f["severity"] == "info" and f["cve_id"] is None
    assert "Clean scan" in f["description"]


def test_unreachable_live_target():
    import triad_scanner as ts
    scanner = ts.TRIAD_Scanner(timeout=2.0)
    doc = scanner.scan("https://triad-definitely-unreachable.invalid", demo=False)
    assert doc["finding_count"] == 1
    assert "Target unreachable" in doc["findings"][0]["description"]


def test_console_ui_served():
    from fastapi.testclient import TestClient
    import server as srv
    client = TestClient(srv.app)
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "TRIAD" in r.text and "Paste any link" in r.text


def test_run_scan_cli():
    import json as _json
    import subprocess
    out = subprocess.run(
        ["python3", "run_scan.py", "--target", "github.com/demo/repo", "--demo"],
        capture_output=True, text=True, timeout=60, check=True)
    doc = _json.loads(out.stdout)
    assert doc["routed_as"] == "github:trivy-dependencies"
    assert doc["finding_count"] > 100
    out = subprocess.run(["python3", "run_scan.py", "--health"],
                          capture_output=True, text=True, timeout=60, check=True)
    assert _json.loads(out.stdout)["templates"] >= 12
