import { NextResponse } from "next/server";
import { execFile } from "child_process";
import path from "path";

const RUNNER = path.join(process.cwd(), "download", "triad", "run_scan.py");
const PY = process.env.PYTHON || "python3";

let cached: { at: number; value: unknown } | null = null;

function engineHealth(): Promise<Record<string, unknown>> {
  return new Promise((resolve) => {
    execFile(
      PY,
      [RUNNER, "--health"],
      { timeout: 20_000, maxBuffer: 1024 * 1024 },
      (err, stdout) => {
        if (err || !stdout) {
          resolve({ status: "offline", engine: "triad_scanner.py", templates: 0 });
          return;
        }
        try {
          resolve(JSON.parse(String(stdout)));
        } catch {
          resolve({ status: "offline", engine: "triad_scanner.py", templates: 0 });
        }
      },
    );
  });
}

export async function GET() {
  if (!cached || Date.now() - cached.at > 300_000) {
    cached = { at: Date.now(), value: await engineHealth() };
  }
  return NextResponse.json(cached.value);
}
