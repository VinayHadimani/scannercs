

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
