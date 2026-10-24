"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  ScanSearch, Loader2, Copy, Download, ExternalLink, Zap, FlaskConical,
  TriangleAlert,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

/* ============================== types ============================== */
type Sev = "critical" | "high" | "medium" | "low" | "info";
type Mode = "live" | "demo";

interface Finding {
  cve_id: string | null;
  target_url: string;
  severity: Sev;
  source_tool: string;
  description: string;
  cwe?: string | null;
  evidence?: string | null;
  fix?: string | null;
}
interface Report {
  target: string;
  routed_as: string;
  demo_mode: boolean;
  scan_id: string;
  started_at: string;
  duration_ms: number;
  finding_count: number;
  findings: Finding[];
}

/* ============================== style maps ============================== */
const SEVS: Sev[] = ["critical", "high", "medium", "low", "info"];
const SEV: Record<Sev, { badge: string; bar: string; text: string }> = {
  critical: { badge: "bg-rose-500/10 text-rose-300 border-rose-500/40", bar: "border-l-rose-400", text: "text-rose-300" },
  high: { badge: "bg-orange-500/10 text-orange-300 border-orange-500/40", bar: "border-l-orange-400", text: "text-orange-300" },
  medium: { badge: "bg-yellow-400/10 text-yellow-300 border-yellow-500/30", bar: "border-l-yellow-300", text: "text-yellow-300" },
  low: { badge: "bg-sky-500/10 text-sky-300 border-sky-500/40", bar: "border-l-sky-400", text: "text-sky-300" },
  info: { badge: "bg-slate-500/10 text-slate-300 border-slate-500/30", bar: "border-l-slate-400", text: "text-slate-300" },
};
const TOOL_STYLE: Record<string, string> = {
  "triad-derived": "text-sky-300 border-sky-500/40 bg-sky-500/5",
  "nuclei-derived": "text-orange-300 border-orange-500/40 bg-orange-500/5",
  "zap-derived": "text-violet-300 border-violet-500/40 bg-violet-500/5",
  "triad-router": "text-slate-400 border-slate-600 bg-slate-800/40",
};
const PANEL = "bg-[#10151c] border-[#1e2836]";
const LINE2 = "#2b3849";

const EXAMPLES: { t: string; m: Mode; label: string }[] = [
  { t: "https://example.com", m: "live", label: "example.com" },
  { t: "github.com/request/request", m: "live", label: "request/request" },
  { t: "https://demo.triad.local", m: "demo", label: "demo.triad.local" },
  { t: "github.com/demo/repo", m: "demo", label: "demo/repo" },
];

const isHttp = (s: string) => /^https?:\/\//i.test(s || "");
const nvdUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;

/* ============================== small parts ============================== */
function Wordmark() {
  return (
    <div className="flex items-baseline gap-1 text-lg font-extrabold tracking-[0.14em] text-slate-100 sm:text-xl">
      TRIAD
      <span
        aria-hidden="true"
        className="ml-1 inline-block h-[1.05em] w-[0.55em] translate-y-[0.16em] animate-pulse bg-emerald-400"
      />
    </div>
  );
}

function SevBadge({ sev }: { sev: Sev }) {
  return (
    <Badge variant="outline" className={`${SEV[sev].badge} text-[10px] font-extrabold uppercase tracking-widest`}>
      {sev}
    </Badge>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  const cls = TOOL_STYLE[tool] ?? "text-slate-400 border-slate-600 bg-slate-800/40";
  return (
    <Badge variant="outline" className={`${cls} font-mono text-[10.5px] font-medium`}>
      {tool}
    </Badge>
  );
}

function FindingCard({ f }: { f: Finding }) {
  const cveOk = f.cve_id && /^CVE-\d{4}-\d+$/i.test(f.cve_id);
  return (
    <li className={`rounded-lg border ${PANEL} border-l-[3px] ${SEV[f.severity].bar} px-4 py-3.5`}>
      <div className="flex flex-wrap items-center gap-2">
        <SevBadge sev={f.severity} />
        {cveOk ? (
          <a
            href={nvdUrl(f.cve_id as string)}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-400/10 px-2.5 py-1 font-mono text-xs font-bold text-emerald-300 transition hover:brightness-125"
          >
            {f.cve_id}
            <ExternalLink className="h-3 w-3" aria-hidden="true" />
          </a>
        ) : (
          <Badge variant="outline" className="border-[#2b3849] bg-transparent text-[11px] font-normal text-slate-400">
            no CVE · configuration issue
          </Badge>
        )}
        <ToolBadge tool={f.source_tool} />
        {f.cwe ? (
          <Badge variant="outline" className="border-dashed border-[#2b3849] bg-transparent font-mono text-[11px] text-slate-400">
            CWE {f.cwe}
          </Badge>
        ) : null}
        {f.fix ? (
          <Badge variant="outline" className="border-dashed border-emerald-700 bg-transparent font-mono text-[11px] text-emerald-300">
            fix → {f.fix}
          </Badge>
        ) : null}
      </div>
      <p className="mt-2.5 text-[13.5px] leading-relaxed text-slate-200">{f.description}</p>
      {f.evidence ? (
        <div className="mt-2.5 rounded-md border border-[#1e2836] bg-[#0a0e13] px-3 py-2 font-mono text-xs leading-relaxed break-all text-slate-400">
          <b className="mr-2 text-[10px] tracking-widest text-yellow-300">EVIDENCE</b>
          {f.evidence}
        </div>
      ) : null}
      {f.target_url ? (
        <div className="mt-2 font-mono text-[11px] break-all text-slate-500">
          via{" "}
          {isHttp(f.target_url) ? (
            <a href={f.target_url} target="_blank" rel="noopener noreferrer" className="text-slate-400 transition hover:text-emerald-300">
              {f.target_url}
            </a>
          ) : (
            f.target_url
          )}
        </div>
      ) : null}
    </li>
  );
}

/* ============================== page ============================== */
export default function Home() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<Mode>("live");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [filter, setFilter] = useState<Sev | "all">("all");
  const [error, setError] = useState<string | null>(null);
  const [showProg, setShowProg] = useState(false);
  const [health, setHealth] = useState<{ status: string; templates: number } | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const progTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const { toast } = useToast();

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json())
      .then((h) => setHealth(h))
      .catch(() => setHealth({ status: "offline", templates: 0 }));
  }, []);

  const doScan = useCallback(
    async (t: string, m: Mode) => {
      const url = t.trim();
      if (!url || busy) return;
      setError(null);
      setReport(null);
      setBusy(true);
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      progTimer.current = setTimeout(() => setShowProg(true), 1200);
      const kill = setTimeout(() => ac.abort(), 90_000);
      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ target: url, demo: m === "demo" }),
          signal: ac.signal,
        });
        const doc = await res.json();
        if (!res.ok) throw new Error(doc?.error || `service responded ${res.status}`);
        setReport(doc as Report);
        setFilter("all");
      } catch (e) {
        const msg =
          e instanceof Error && e.name === "AbortError"
            ? "Scan timed out (90s). The target may be unreachable — verify the URL, or try DEMO mode."
            : `Scan failed: ${e instanceof Error ? e.message : "service unreachable"}`;
        setError(msg);
      } finally {
        clearTimeout(kill);
        if (progTimer.current) clearTimeout(progTimer.current);
        setShowProg(false);
        setBusy(false);
      }
    },
    [busy],
  );

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: report?.finding_count ?? 0 };
    SEVS.forEach((s) => (c[s] = 0));
    report?.findings.forEach((f) => (c[f.severity] = (c[f.severity] ?? 0) + 1));
    return c;
  }, [report]);

  const shown = useMemo(
    () => (report?.findings ?? []).filter((f) => filter === "all" || f.severity === filter),
    [report, filter],
  );

  const copyJson = async () => {
    if (!report) return;
    const text = JSON.stringify(report, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      toast({ title: "Report JSON copied to clipboard" });
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        toast({ title: "Report JSON copied to clipboard" });
      } catch {
        toast({ title: "Copy failed", variant: "destructive" });
      }
      ta.remove();
    }
  };

  const downloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${report.scan_id || "triad-report"}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  };

  const segBtn = (active: boolean) =>
    `flex items-center gap-1.5 rounded-md px-3 py-2 text-xs font-semibold tracking-widest transition focus-visible:outline focus-visible:ring-2 focus-visible:ring-emerald-400 ${
      active ? "bg-emerald-400/10 text-emerald-300" : "text-slate-400 hover:text-slate-200"
    }`;

  return (
    <div className="flex min-h-screen flex-col bg-[#0a0e13] text-slate-200">
      {/* header */}
      <header className="border-b border-[#1e2836] bg-[radial-gradient(60%_180%_at_15%_-40%,rgba(52,211,153,0.07),transparent_60%)] bg-[#10151c]">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-4 sm:px-6">
          <Wordmark />
          <p className="min-w-[220px] flex-1 border-l border-[#2b3849] pl-4 text-xs leading-relaxed text-slate-400">
            single-input vulnerability scanner — <span className="text-slate-200">trivy</span> ·{" "}
            <span className="text-slate-200">nuclei</span> ·{" "}
            <span className="text-slate-200">zap</span> detection logic, synthesized into one engine
          </p>
          <div
            className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs ${
              health?.status === "ok"
                ? "border-emerald-500/40 text-slate-200"
                : "border-[#2b3849] text-slate-500"
            }`}
            role="status"
          >
            <span
              className={`h-[7px] w-[7px] rounded-full ${
                health?.status === "ok" ? "bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.7)]" : "bg-slate-600"
              }`}
            />
            {health?.status === "ok" ? `engine online · ${health.templates} templates` : "connecting…"}
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-8 sm:px-6">
        {/* scan card */}
        <Card className={`${PANEL} border shadow-[0_8px_30px_rgba(0,0,0,0.35)]`}>
          <CardHeader className="pb-2">
            <CardTitle className="text-xl font-bold text-slate-100">Paste any link</CardTitle>
            <p className="text-[13px] leading-relaxed text-slate-400">
              a GitHub repo → dependency CVE scan (<code className="text-emerald-300">trivy</code> lane) ·
              a website URL → live template + passive checks (<code className="text-emerald-300">nuclei</code> +{" "}
              <code className="text-emerald-300">zap</code> lanes)
            </p>
          </CardHeader>
          <CardContent>
            <form
              className="flex flex-col gap-2.5 sm:flex-row"
              onSubmit={(e) => {
                e.preventDefault();
                doScan(target, mode);
              }}
            >
              <div
                className="flex gap-1 self-stretch rounded-lg border border-[#2b3849] bg-[#0a0e13] p-1"
                role="group"
                aria-label="Scan mode"
              >
                <button type="button" aria-pressed={mode === "live"} onClick={() => setMode("live")} className={segBtn(mode === "live")}>
                  <Zap className="h-3.5 w-3.5" aria-hidden="true" />
                  LIVE
                </button>
                <button type="button" aria-pressed={mode === "demo"} onClick={() => setMode("demo")} className={segBtn(mode === "demo")}>
                  <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" />
                  DEMO
                </button>
              </div>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={busy}
                inputMode="url"
                spellCheck={false}
                aria-label="Target URL"
                placeholder="https://example.com · github.com/expressjs/express"
                className="flex-1 rounded-lg border-[#2b3849] bg-[#0a0e13] font-mono text-[15px] text-slate-200 placeholder:text-slate-600 focus-visible:border-emerald-400 focus-visible:ring-emerald-400/20"
              />
              <Button
                type="submit"
                disabled={busy || !target.trim()}
                className="gap-2 rounded-lg bg-emerald-400 px-6 text-[13px] font-extrabold tracking-widest text-[#0a0e13] hover:bg-emerald-300 disabled:saturate-50 disabled:brightness-75"
              >
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> : <ScanSearch className="h-4 w-4" aria-hidden="true" />}
                {busy ? "SCANNING" : "SCAN"}
              </Button>
            </form>

            <div className="mt-3.5 flex flex-wrap items-center gap-2">
              <span className="text-xs tracking-widest text-slate-600">TRY:</span>
              {EXAMPLES.map((ex) => (
                <Button
                  key={ex.t}
                  variant="outline"
                  size="sm"
                  disabled={busy}
                  onClick={() => {
                    setTarget(ex.t);
                    setMode(ex.m);
                    doScan(ex.t, ex.m);
                  }}
                  className="h-auto rounded-full border-[#2b3849] px-3 py-1.5 text-xs text-slate-400 hover:border-emerald-400 hover:bg-emerald-400/10 hover:text-emerald-300 [&>span]:mr-1.5 [&>span]:text-[10px] [&>span]:tracking-widest [&>span]:text-slate-600 [&>span:hover]:text-inherit"
                >
                  {ex.label}
                  <span>{ex.m.toUpperCase()}</span>
                </Button>
              ))}
            </div>

            <p className="mt-3.5 flex items-start gap-2.5 rounded-lg border border-amber-500/25 bg-amber-400/5 px-3 py-2.5 text-xs leading-relaxed text-amber-200/80">
              <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              Live mode sends real HTTP requests to the target. Only scan assets you own or are
              explicitly authorized to test.
            </p>

            <p
              role="status"
              className={`mt-3.5 font-mono text-xs text-emerald-300 ${showProg ? "" : "hidden"}`}
            >
              {mode === "live"
                ? "engine running — live requests in flight (unreachable targets can take ~60s)…"
                : "engine running…"}
            </p>

            {error ? (
              <p role="alert" className="mt-3.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-[13px] text-rose-200">
                {error}
              </p>
            ) : null}
          </CardContent>
        </Card>

        {/* report */}
        {report ? (
          <motion.section
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3 }}
            aria-live="polite"
            className="mt-8"
          >
            <Card className={`${PANEL} rounded-b-none`}>
              <CardHeader className="pb-3">
                <div className="flex flex-wrap items-center gap-3">
                  {isHttp(report.target) ? (
                    <a
                      href={report.target}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="break-all font-mono text-base font-semibold text-emerald-300 hover:brightness-125"
                    >
                      {report.target}
                    </a>
                  ) : (
                    <span className="break-all font-mono text-base font-semibold text-emerald-300">{report.target}</span>
                  )}
                  <Badge
                    variant="outline"
                    className={`ml-auto text-[10px] font-bold tracking-widest ${
                      report.demo_mode
                        ? "border-sky-500/45 bg-sky-500/10 text-sky-300"
                        : "border-orange-500/45 bg-orange-500/10 text-orange-300"
                    }`}
                  >
                    {report.demo_mode ? "DEMO" : "LIVE"}
                  </Badge>
                </div>
                <div className="mt-2.5 flex flex-wrap gap-2">
                  <Badge variant="outline" className="border-[#2b3849] bg-[#0a0e13] font-mono text-[11px] text-slate-400">
                    route <b className="ml-1 font-semibold text-violet-300">{report.routed_as}</b>
                  </Badge>
                  <Badge variant="outline" className="border-[#2b3849] bg-[#0a0e13] font-mono text-[11px] text-slate-400">
                    duration <b className="ml-1 font-semibold text-slate-200">{report.duration_ms} ms</b>
                  </Badge>
                  <Badge variant="outline" className="border-[#2b3849] bg-[#0a0e13] font-mono text-[11px] text-slate-400">
                    start <b className="ml-1 font-semibold text-slate-200">{report.started_at}</b>
                  </Badge>
                  <Badge variant="outline" className="border-[#2b3849] bg-[#0a0e13] font-mono text-[11px] text-slate-600">
                    {report.scan_id}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6" role="group" aria-label="Filter by severity">
                  {(["all", ...SEVS] as const).map((sev) => {
                    const n = counts[sev] ?? 0;
                    const active = filter === sev;
                    const zero = n === 0 && sev !== "all";
                    return (
                      <button
                        key={sev}
                        type="button"
                        aria-pressed={active}
                        disabled={busy}
                        onClick={() => setFilter(sev)}
                        className={`rounded-lg border bg-[#141b24] px-2 py-2.5 text-center transition focus-visible:outline focus-visible:ring-2 focus-visible:ring-emerald-400 ${
                          active ? "border-emerald-400 bg-emerald-400/10" : "border-[#1e2836] hover:border-[#2b3849]"
                        } ${zero ? "opacity-40" : ""}`}
                      >
                        <span className={`block text-xl font-extrabold leading-none ${sev === "all" ? "text-slate-200" : SEV[sev].text}`}>{n}</span>
                        <span className={`mt-1 block text-[10px] uppercase tracking-widest ${sev === "all" ? "text-slate-500" : SEV[sev].text} opacity-80`}>
                          {sev === "all" ? "total" : sev}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {shown.length ? (
              <ul className="triad-scroll mt-3.5 max-h-[70vh] space-y-2.5 overflow-y-auto pr-1">
                {shown.map((f, i) => (
                  <FindingCard key={`${f.cve_id ?? "cfg"}-${f.target_url}-${i}`} f={f} />
                ))}
              </ul>
            ) : (
              <div className="mt-3.5 rounded-xl border border-emerald-500/30 bg-[#10151c] px-6 py-6 text-center">
                <p className="text-base font-bold text-emerald-300">No matching findings</p>
                <p className="mt-1.5 text-[13px] text-slate-400">
                  {report.finding_count
                    ? `All ${report.finding_count} findings are hidden by the active filter.`
                    : "Target reachable — no template matched and no passive rule fired."}
                </p>
              </div>
            )}

            <div className="mt-4 flex flex-wrap items-center gap-2.5 rounded-b-lg border border-t-0 border-[#1e2836] bg-[#10151c] px-5 py-3.5">
              <span className="mr-auto font-mono text-xs text-slate-400">
                showing <b className="text-slate-200">{shown.length}</b> / {report.finding_count} findings ·{" "}
                {report.demo_mode ? "demo" : "live"}
              </span>
              <Button variant="outline" size="sm" onClick={copyJson} className="gap-2 rounded-md border-[#2b3849] text-slate-400 hover:border-emerald-400 hover:bg-emerald-400/10 hover:text-emerald-300">
                <Copy className="h-3.5 w-3.5" aria-hidden="true" /> copy JSON
              </Button>
              <Button variant="outline" size="sm" onClick={downloadJson} className="gap-2 rounded-md border-[#2b3849] text-slate-400 hover:border-emerald-400 hover:bg-emerald-400/10 hover:text-emerald-300">
                <Download className="h-3.5 w-3.5" aria-hidden="true" /> download JSON
              </Button>
            </div>
          </motion.section>
        ) : null}
      </main>

      <footer className="mt-auto border-t border-[#1e2836] py-5">
        <p className="mx-auto max-w-4xl px-4 text-center text-[11.5px] leading-relaxed tracking-wide text-slate-600 sm:px-6">
          TRIAD console · engine: <code className="text-slate-500">triad_scanner.py</code> · api:{" "}
          <code className="text-slate-500">POST /api/scan</code> · <code className="text-slate-500">GET /api/health</code>
        </p>
      </footer>
    </div>
  );
}
