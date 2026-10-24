import { NextRequest, NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";

const RUNNER = path.join(process.cwd(), "download", "triad", "run_scan.py");
const PY = process.env.PYTHON || "python3";
const SCAN_LIMIT_MS = 110_000;          // hard ceiling; UI aborts at 90s
const MAX_BUFFER = 32 * 1024 * 1024;    // 185-finding reports are ~300 KB

interface SpawnResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

function run(args: string[], timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolve) => {
    execFile(
      PY,
      [RUNNER, ...args],
      { timeout: timeoutMs, maxBuffer: MAX_BUFFER, cwd: path.dirname(RUNNER) },
      (err, stdout, stderr) => {
        const e = err as (NodeJS.ErrnoException & { code?: unknown }) | null;
        const killed = e?.killed === true;
        resolve({
          code: e ? (typeof e.code === "number" ? e.code : 1) : 0,
          stdout: String(stdout ?? ""),
          stderr: String(stderr ?? (err ? err.message : "")),
          timedOut: killed,
        });
      },
    );
  });
}

export async function POST(req: NextRequest) {
  let body: { target?: unknown; demo?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
  }

  const target = typeof body.target === "string" ? body.target.trim().slice(0, 2000) : "";
  if (!target) {
    return NextResponse.json({ error: "target is required" }, { status: 400 });
  }
  const args = ["--target", target, "--timeout", "6"];
  if (body.demo === true) args.push("--demo");
  else if (body.demo === false) args.push("--live");

  const res = await run(args, SCAN_LIMIT_MS);
  if (res.timedOut) {
    return NextResponse.json(
      { error: `scan timed out after ${SCAN_LIMIT_MS / 1000}s (target too slow or unreachable)` },
      { status: 504 },
    );
  }
  if (res.code === 0 && res.stdout) {
    try {
      const report = JSON.parse(res.stdout);
      return NextResponse.json(report);
    } catch {
      return NextResponse.json({ error: "engine produced invalid JSON" }, { status: 502 });
    }
  }
  return NextResponse.json(
    { error: (res.stderr || "engine failed").split("\n").slice(-2).join(" ").slice(0, 300) },
    { status: 502 },
  );
}
