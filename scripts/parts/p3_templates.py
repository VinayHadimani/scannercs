

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
