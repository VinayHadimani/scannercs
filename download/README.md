# TRIAD Scanner — Deliverables

All files are available **loosely** in this folder (no archive needed). If the archive
files work for you, `triad-scanner.zip` and `triad-scanner.tar.gz` (same content) are
also here — but nothing is archive-only.

## Quick start

```bash
cd triad
pip install -r requirements.txt
python -m pytest tests/ -q          # 49 tests pass offline
uvicorn server:app --port 8000      # POST /scan  (demo mode on by default)
```

## File map — `triad/`

| File | Purpose |
|------|---------|
| `triad_scanner.py` | The single-module scanner. Trivy-derived dependency/CVE matching, Nuclei-derived YAML template engine (matchers/extractors), ZAP-derived passive web checks (13 rules). |
| `server.py` | FastAPI app exposing `POST /scan`. Accepts a GitHub repo URL or a live website URL, auto-routes, returns the standardized findings JSON. Demo mode default ON (env `TRIAD_DEMO_MODE`, or per-request `"demo": false` for live scans). |
| `requirements.txt` | Python dependencies (fastapi, uvicorn, httpx, pyyaml, pytest). |
| `README.md` | Full architecture doc: how the three tools' logic was reverse-engineered and merged. |
| `triad_templates/*.yaml` (12) | Nuclei-derived detection templates: Apache path traversal CVE-2021-41773, .env exposure, CORS misconfig, .git HEAD + config exposure, phpinfo, Spring Boot Actuator, Tomcat manager, Jenkins, Swagger UI, open directory listing, tech fingerprint. |
| `data/dep_cve_index.json` | OSV-derived CVE index (798 advisories, 55 packages) built from the live OSV API with Trivy/OSV `range.go` semantics. Rebuild: `scripts/build_dep_index.py`. |
| `data/demo/` | DEMO_MODE fixtures: `package.json`, `requirements.txt`, `web_fixture.json` (10 vulnerable routes). |
| `scripts/build_dep_index.py` | Rebuilds the CVE index from the live OSV API. |
| `tests/test_triad.py` | 49 offline tests covering all three detection lanes (12 templates, 13 ZAP rules) + output contract + FastAPI. |
| `tests/fixture_server.py` | Local HTTP fixture server ("vulnerable target") used by web-lane tests and manual demos. |

## Output contract (every finding)

```json
{
  "cve_id": "CVE-2024-29041",
  "target_url": "https://github.com/.../package.json",
  "severity": "high",
  "source_tool": "triad-derived",
  "description": "express 4.18.1 ... (for TRIAD's NVD/EPSS enrichment)"
}
```

Exactly the five required keys on every finding (`cve_id`, `target_url`, `severity`,
`source_tool`, `description`) plus optional `cwe`, `evidence`, `fix` context.
