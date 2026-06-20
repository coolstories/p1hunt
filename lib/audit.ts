import { appendFile, mkdir, readFile, writeFile } from "fs/promises";
import path from "path";
import type { AuditEvent, EnterpriseConfig, ScanResult } from "./types";

export function createRunId(prefix = "run") {
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const random = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${timestamp}_${random}`;
}

export function createAuditEvent(
  runId: string,
  actor: AuditEvent["actor"],
  action: string,
  detail: string,
  extra: Partial<Pick<AuditEvent, "target" | "decision">> = {}
): AuditEvent {
  return {
    id: createRunId("evt"),
    runId,
    timestamp: new Date().toISOString(),
    actor,
    action,
    detail,
    ...extra
  };
}

export async function appendAuditEvent(config: EnterpriseConfig, event: AuditEvent) {
  await mkdir(config.auditDirectory, { recursive: true });
  await appendFile(auditPath(config, event.runId), `${JSON.stringify(event)}\n`, "utf8");
}

export async function appendAuditEvents(config: EnterpriseConfig, events: AuditEvent[]) {
  for (const event of events) {
    await appendAuditEvent(config, event);
  }
}

export async function writeRunJson(config: EnterpriseConfig, scan: ScanResult) {
  if (!scan.run?.jsonPath) {
    return;
  }
  await mkdir(path.dirname(scan.run.jsonPath), { recursive: true });
  await writeFile(scan.run.jsonPath, `${JSON.stringify(scan, null, 2)}\n`, "utf8");
}

export async function readAuditTail(config: EnterpriseConfig, runId: string, limit = 40) {
  try {
    const raw = await readFile(auditPath(config, runId), "utf8");
    return raw
      .trim()
      .split("\n")
      .filter(Boolean)
      .slice(-limit)
      .map((line) => JSON.parse(line) as AuditEvent);
  } catch {
    return [];
  }
}

export function auditPath(config: EnterpriseConfig, runId: string) {
  return path.join(config.auditDirectory, `${runId}.jsonl`);
}
