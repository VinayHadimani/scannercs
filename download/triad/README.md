# TRIAD Scanner

A lightweight unified vulnerability scanner synthesized by **reverse-engineering
the core detection mechanisms** of three industry tools, then merging them into
one pure-Python module (~1,300 lines, zero heavy dependencies):

| Lane | Derived from | What it does |
|---|---|---|
| Dependency | **Trivy** (aquasecurity) | parses package.json / requirements.txt / pyproject.toml, matches package versions against an OSV-derived CVE index with trivy's exact `IsVulnerable` semantics |
| Template | **Nuclei** (projectdiscovery) | runs YAML detection templates: word/regex/status matchers, regex/kval/json extractors, `{{BaseURL}}` interpolation, custom request headers |
| Passive | **ZAP** (zaproxy) | passive HTTP-response security rules ported 1:1 from zap-extensions pscanrules (plugin ids, risk levels, CWEs preserved) |

## Quick start

```bash
cd triad
pip install -r requirements.txt

# as a library
python3 -c "
from triad_scanner import TRIAD_Scanner
import json
r = TRIAD_Scanner().scan('https://github.com/expressjs/express')
print(json.dumps(r['findings'][:2], indent=2))"

# as a service
uvicorn server:app --port 8000
curl -X POST localhost:8000/scan -H 'Content-Type: application/json' \
     -d '{"target": "http://localhost:3000", "demo": false}'

# tests (offline, no network needed)
python3 -m pytest tests/ -q          # 49 tests
```

## Input routing (single input, automatic)

| You paste | TRIAD does |
|---|---|
| `https://github.com/owner/repo` | downloads repo tarball, dependency lane (Trivy-derived) |
| `http(s)://site` or `site.example.com` | template lane (Nuclei-derived) + passive lane (ZAP-derived) |
| `/local/dir` | dependency lane on a local checkout |

## Output contract (every finding)

```json
{
  "cve_id": "CVE-2024-29041",
  "target_url": "https://github.com/owner/repo/package.json",
  "severity": "high",
  "source_tool": "triad-derived",
  "description": "express 4.18.1 is affected by CVE-2024-29041 ... Ready for NVD/EPSS enrichment.",
  "cwe": "CWE-1333",
  "evidence": "express@4.18.1 in package.json",
  "fix": "4.20.0"
}
```

`cve_id` is null for misconfiguration findings (ZAP rules / non-CVE templates) —
those carry `cwe` instead, feeding the EXPLAIN/RAG stage.

## DEMO_MODE

`DEMO_MODE` mocks the **target**, never the **engine**: the real matching code
always runs, only the HTTP responses / repo files come from bundled fixtures —
instant, zero network. Perfect for demo-day crash insurance.

- Library: `scanner.scan(target, demo=True)`
- Env: `TRIAD_DEMO_MODE=1` (server + library)
- FastAPI: `POST /scan {"target": ..., "demo": true|false}`.
  Default resolution: request `demo` field > `TRIAD_DEMO_MODE` env > **ON**
  (safe default). Pass `"demo": false` for a live scan.

## Data provenance (no hallucinated vulnerability data)

- `data/dep_cve_index.json` — built from the **live OSV API**
  (`https://api.osv.dev`), 798 advisories across 55 popular npm/PyPI packages,
  converted with trivy-db's `range.go` semantics. Rebuild anytime:
  `python3 scripts/build_dep_index.py`
- Severity comes from OSV `database_specific.severity` (CVSS vector fallback,
  conservative bucket), never invented.
- ZAP rules keep their upstream plugin ids / risk / CWE ids verbatim.

## Reverse-engineering provenance (per lane)

**Trivy lane** — trivy v0.76.1 (aquasecurity/trivy + aquasecurity/trivy-db):
- manifest parsers: `pkg/dependency/parser/nodejs/packagejson/parse.go`,
  `pkg/dependency/parser/nodejs/npm/parse.go`, `pkg/dependency/parser/python/pip/parse.go`
- detection flow: `pkg/detector/library/driver.go` (`DetectVulnerabilities`)
- matching semantics: `pkg/detector/library/compare/compare.go` (`IsVulnerable`:
  fail-open on empty ranges, vulnerable OR-groups, patched exclusion) with the npm
  comparer (`go-npm-version`, prerelease-enabled full ordering) and PEP 440 comparer
- index build: trivy-db `pkg/vulnsrc/osv/{osv,range}.go`
- REA binary-level confirmation: trivy 0.76.1 embeds `aquasecurity/trivy-db`,
  `aquasecurity/go-version`, `Masterminds/semver/v3`, `blang/semver/v4` (Go 1.27.3)

**Nuclei lane** — nuclei v3.11.1 (projectdiscovery/nuclei):
- matchers-condition default OR: `pkg/operators/operators.go` (Compile)
- word/regex/status matchers, per-matcher conditions, negative, case-insensitive:
  `pkg/operators/matchers/match.go`
- parts mapping (`body` default, `header` -> all headers, `all`, `response`) and the
  response event map: `pkg/protocols/http/operators.go`
- extractors (regex group / kval / json): `pkg/operators/extractors/extract.go`
- `{{BaseURL}}`-style interpolation: `pkg/protocols/http/build_request.go`
- template `classification.cve-id` / `cwe-id` / `severity`: `pkg/model/model.go`

**ZAP lane** — zaproxy weekly + zap-extensions `pscanrules`:
- passive framework: `org.zaproxy.zap.extension.pscan.PassiveScanner` (zaproxy core)
- ported rules (exact trigger conditions, risk levels, CWE ids, plugin ids):
  10036 ServerHeaderInfoLeak, 10037 XPoweredByHeaderInfoLeak, 10010 CookieHttpOnly,
  10011 CookieSecureFlag, 10035 StrictTransportSecurity, 10021 XContentTypeOptions,
  10038 ContentSecurityPolicyMissing, 10015 CacheControl, 10098 CrossDomainMisconfig,
  10023 InformationDisclosureDebugErrors (29 upstream patterns from
  `zapHomeFiles/xml/debug-error-messages.txt`), 10024 InformationDisclosureInUrl
  (name tokens from `URL-information-disclosure-messages.txt` + email/CC/SSN value
  patterns from `InformationDisclosureInUrlScanRule.java`), 10054 CookieSameSite
  (missing/None/invalid-value alert refs), 10020 AntiClickjacking (XFO
  missing/malformed/multiple; CSP `frame-ancestors` precedence)
- cookie attribute/expiry helpers: `addOns/commonlib/.../CookieUtils.java`
- REA artifact-level confirmation: ZAP weekly ships `pscanrules-release-78.zap`,
  `pscan-alpha-0.7.0.zap`, `automation-beta` inside the distribution

## Deliberate subset (lightweight for the hackathon)

- Matchers: `status`, `word`, `regex` (DSL/binary/xpath/LLM matchers out of scope)
- Extractors: `regex` (group), `kval`, `json` (dotted path + `[N]`, not full jq)
- Manifests: `package.json`, `requirements.txt`, `pyproject.toml`; range specs in
  package.json are approximated by their lower bound (exact pins preferred)
- Template engine: GET requests (with per-template custom headers),
  `{{BaseURL}}/{{RootURL}}/{{Host}}/{{Scheme}}`,
  optional redirects with `max-redirects`; raw requests, fuzzing, pipelines excluded
- Passive lane: the fetched root response (ZAP baseline = spider + passive; no active scan)

## Bundled templates (12)

| Template | Severity | Engine features exercised |
|---|---|---|
| apache-path-traversal-cve-2021-41773 | high | word+status AND, regex extractor |
| dot-env-file-exposure | high | word+status AND, regex extractor |
| cors-misconfiguration | medium | custom Origin header, case-insensitive header regex, kval |
| git-config-exposure | medium | word+status AND, regex extractor |
| git-head-exposure | medium | word+status AND |
| phpinfo-exposure | medium | multi-path probes, regex extractor |
| springboot-actuator-exposed | medium | json extractor (dotted paths) |
| tomcat-manager-exposed | medium | status list (200/401), regex extractor |
| open-directory-listing | low | word+status AND |
| jenkins-detection | info | status list (200/401/403), multi-word OR |
| swagger-ui-exposed | info | multi-path, multi-word OR |
| tech-server-header | info | kval extractors |

Adding coverage is just dropping a YAML file into `triad_templates/` — no code
changes needed (Nuclei template format subset documented above).

## Ethics / authorization

The template lane sends a handful of read-only GET requests to the target you name.
Only scan targets you are authorized to scan (your own apps, the bundled fixture
server, deliberately-vulnerable practice apps like OWASP Juice Shop, or in-scope
bug-bounty targets). The demo fixtures exist so you never need to point it at
anyone else's infrastructure.

## Tests

```bash
python3 -m pytest tests/ -q      # 49 tests: engines, parsers, rules, live fixture, API
python3 tests/fixture_server.py  # stand-alone "vulnerable target" for manual demos
```
