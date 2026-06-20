#!/usr/bin/env node
import { mkdir, writeFile } from "fs/promises";
import path from "path";
import { createInterface } from "readline/promises";
import { stdin as input, stdout as output } from "process";
import { getAccountStatus } from "../lib/account";
import {
  appendAuditEvent,
  appendAuditEvents,
  createAuditEvent,
  createRunId,
  readAuditTail,
  writeRunJson
} from "../lib/audit";
import {
  initializeEnterpriseConfig,
  loadEnterpriseConfig,
  writeEnterpriseConfig
} from "../lib/enterprise-config";
import { renderMarkdownReport } from "../lib/report";
import { getDefaultScanOptions, scanRepository } from "../lib/repository-scanner";
import { createSampleEngagement } from "../lib/sample-engagement";
import type {
  AccountStatus,
  EnterpriseConfig,
  RunMetadata,
  ScanOptions,
  ScanResult
} from "../lib/types";
import {
  banner,
  color,
  printFindings,
  printHelp,
  printHuntRound,
  printSafeReminder,
  printScanSummary,
  printTriage
} from "./terminal";

interface CliState {
  rootPath: string;
  enableClaudeTriage: boolean;
  maxFiles: number;
  lastScan: ScanResult | null;
  config: EnterpriseConfig;
  account: AccountStatus;
}

const huntFrames = [
  "critical authorization boundary search",
  "trusted execution and command boundary search",
  "secret, signing, and supply-chain custody search",
  "data exposure and tenant isolation search",
  "business-logic invariant search",
  "smart-contract custody and upgradeability search"
];

async function main() {
  const args = process.argv.slice(2);
  const config = await loadEnterpriseConfig(process.cwd());
  const account = await getAccountStatus();
  const state: CliState = {
    rootPath: config.defaultRootPath,
    enableClaudeTriage: config.enableClaudeTriage,
    maxFiles: config.maxFiles,
    lastScan: null,
    config,
    account
  };

  if (args.length > 0) {
    await runCommand(args, state);
    return;
  }

  banner();
  printEnterpriseStatus(state);
  printSafeReminder();

  const rl = createInterface({ input, output, prompt: color.cyan("p1scan> ") });
  rl.prompt();

  for await (const line of rl) {
    const parts = splitCommand(line);
    if (!parts.length) {
      rl.prompt();
      continue;
    }

    try {
      const shouldExit = await runCommand(parts, state);
      if (shouldExit) {
        break;
      }
    } catch (error) {
      console.error(color.red(error instanceof Error ? error.message : "Command failed."));
    }

    rl.prompt();
  }

  rl.close();
}

async function runCommand(parts: string[], state: CliState): Promise<boolean> {
  const command = parts[0];
  const args = parts.slice(1);

  switch (command) {
    case "help":
    case "--help":
    case "-h":
      printHelp();
      return false;
    case "init":
      state.config = await initializeEnterpriseConfig(process.cwd());
      console.log(color.green(`Enterprise config initialized at ${process.cwd()}/.p1scan/config.json`));
      return false;
    case "status":
      state.account = await getAccountStatus();
      printEnterpriseStatus(state);
      return false;
    case "config":
      await updateConfig(args, state);
      return false;
    case "scan":
      state.lastScan = await runScan(args, state);
      printScanSummary(state.lastScan);
      printFindings(state.lastScan.findings, 8);
      return false;
    case "hunt":
      state.lastScan = await runHunt(args, state);
      return false;
    case "findings":
      requireScan(state);
      printFindings(state.lastScan.findings, 20);
      return false;
    case "agent":
      requireScan(state);
      printTriage(state.lastScan);
      return false;
    case "audit":
      requireScan(state);
      await printAudit(state);
      return false;
    case "report":
      requireScan(state);
      await exportReport(args[0] ?? defaultReportPath(state), state.lastScan, state);
      return false;
    case "scope":
      printScope();
      return false;
    case "quit":
    case "exit":
      return true;
    default:
      throw new Error(`Unknown command: ${command}. Type "help" for commands.`);
  }
}

async function runScan(args: string[], state: CliState): Promise<ScanResult> {
  const parsed = parseOptions(args, state);
  Object.assign(state, parsed.statePatch);

  console.log(color.bold(`\nScanning ${parsed.rootPath}`));
  printSafeReminder();

  const run = createRunMetadata("scan", parsed.rootPath, parsed.reportPath, parsed.jsonPath, state);
  await appendAuditEvent(
    state.config,
    createAuditEvent(run.runId, "operator", "scan.start", "Repository scan started.", {
      target: parsed.rootPath
    })
  );

  const scan = await scanRepository(
    parsed.options,
    createSampleEngagement().policy,
    createSampleEngagement().scope
  );
  scan.run = finishRun(run);
  await persistRun(scan, state);
  if (parsed.reportPath) {
    await exportReport(parsed.reportPath, scan, state);
  }
  return scan;
}

async function runHunt(args: string[], state: CliState): Promise<ScanResult> {
  const parsed = parseOptions(args, state);
  Object.assign(state, parsed.statePatch);

  const rounds = parsed.rounds ?? 3;
  const run = createRunMetadata("hunt", parsed.rootPath, parsed.reportPath, parsed.jsonPath, state);
  let latest: ScanResult | null = null;

  console.log(color.bold(`\nAutonomous P1 hunt started for ${parsed.rootPath}`));
  printSafeReminder();
  await appendAuditEvent(
    state.config,
    createAuditEvent(run.runId, "operator", "hunt.start", `Autonomous hunt started for ${rounds} round(s).`, {
      target: parsed.rootPath
    })
  );

  for (let round = 1; round <= rounds; round += 1) {
    const frame = huntFrames[(round - 1) % huntFrames.length];
    printHuntRound(round, frame);

    latest = await scanRepository(
      {
        ...parsed.options,
        enableClaudeTriage: parsed.options.enableClaudeTriage || round > 1
      },
      createSampleEngagement().policy,
      createSampleEngagement().scope
    );
    latest.run = { ...run, finishedAt: new Date().toISOString() };
    await appendAuditEvent(
      state.config,
      createAuditEvent(
        run.runId,
        "scanner",
        "hunt.round",
        `Round ${round} completed with ${latest.summary.criticalCandidates} critical candidate(s).`,
        { target: frame }
      )
    );

    printScanSummary(latest);
    printFindings(latest.findings, 5);

    if (latest.summary.criticalCandidates > 0) {
      console.log(
        color.red(
          "\nP1 candidates found. Stopping autonomous hunt for human review and safe reproduction."
        )
      );
      printTriage(latest);
      latest.run = finishRun(run);
      await persistRun(latest, state);
      if (parsed.reportPath) {
        await exportReport(parsed.reportPath, latest, state);
      }
      return latest;
    }

    console.log(
      color.yellow(
        "No critical candidate survived this round. Reframing the search lens without increasing aggressiveness."
      )
    );
  }

  if (!latest) {
    throw new Error("Hunt did not run.");
  }

  console.log(color.yellow("\nNo P1 candidate found in bounded safe search rounds."));
  printTriage(latest);
  latest.run = finishRun(run);
  await persistRun(latest, state);
  if (parsed.reportPath) {
    await exportReport(parsed.reportPath, latest, state);
  }
  return latest;
}

async function exportReport(filePath: string, scan: ScanResult, state: CliState) {
  const resolved = path.resolve(filePath);
  await mkdir(path.dirname(resolved), { recursive: true });
  await writeFile(resolved, renderMarkdownReport(scan), "utf8");
  await appendAuditEvent(
    state.config,
    createAuditEvent(
      scan.run?.runId ?? createRunId("run"),
      "scanner",
      "report.write",
      "Markdown report exported.",
      { target: resolved }
    )
  );
  console.log(color.green(`Report written to ${resolved}`));
}

function parseOptions(args: string[], state: CliState) {
  let rootPath = state.rootPath;
  let enableClaudeTriage = state.enableClaudeTriage;
  let maxFiles = state.maxFiles;
  let rounds: number | undefined;
  let reportPath: string | undefined;
  let jsonPath: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--agent") {
      enableClaudeTriage = true;
      continue;
    }
    if (arg === "--no-agent") {
      enableClaudeTriage = false;
      continue;
    }
    if (arg === "--max-files") {
      maxFiles = Number(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--rounds") {
      rounds = Number(args[index + 1]);
      index += 1;
      continue;
    }
    if (arg === "--report") {
      reportPath = args[index + 1] ?? "p1scan-report.md";
      index += 1;
      continue;
    }
    if (arg === "--json") {
      jsonPath = args[index + 1] ?? defaultJsonPath(state);
      index += 1;
      continue;
    }
    if (arg === "--policy") {
      state.config.policyProfile = parsePolicy(args[index + 1]);
      index += 1;
      continue;
    }
    if (!arg.startsWith("--")) {
      rootPath = path.resolve(arg);
      continue;
    }
    throw new Error(`Unknown option: ${arg}`);
  }

  if (!Number.isFinite(maxFiles) || maxFiles < 1) {
    throw new Error("--max-files must be a positive number.");
  }

  if (rounds !== undefined && (!Number.isFinite(rounds) || rounds < 1)) {
    throw new Error("--rounds must be a positive number.");
  }

  const options: ScanOptions = {
    ...getDefaultScanOptions(rootPath),
    rootPath,
    maxFiles: Math.min(maxFiles, 1_500),
    enableClaudeTriage
  };

  return {
    rootPath,
    rounds,
    reportPath,
    jsonPath,
    options,
    statePatch: {
      rootPath,
      maxFiles: options.maxFiles,
      enableClaudeTriage
    }
  };
}

async function updateConfig(args: string[], state: CliState) {
  if (!args.length || args[0] === "show") {
    console.log(JSON.stringify(state.config, null, 2));
    return;
  }

  if (args[0] === "set") {
    const [key, value] = args.slice(1);
    if (!key || value === undefined) {
      throw new Error("Usage: config set <key> <value>");
    }
    if (key === "organization") {
      state.config.organization = value;
    } else if (key === "policyProfile") {
      state.config.policyProfile = parsePolicy(value);
    } else if (key === "maxFiles") {
      state.config.maxFiles = Number(value);
      state.maxFiles = state.config.maxFiles;
    } else if (key === "enableClaudeTriage") {
      state.config.enableClaudeTriage = value === "true" || value === "1";
      state.enableClaudeTriage = state.config.enableClaudeTriage;
    } else {
      throw new Error(`Unsupported config key: ${key}`);
    }
    await writeEnterpriseConfig(state.config, process.cwd());
    console.log(color.green(`Config updated: ${key}`));
    return;
  }

  throw new Error("Usage: config show | config set <key> <value>");
}

async function persistRun(scan: ScanResult, state: CliState) {
  if (!scan.run) {
    return;
  }

  await appendAuditEvents(state.config, [
    createAuditEvent(
      scan.run.runId,
      "scanner",
      "scan.finish",
      `Scan finished with ${scan.summary.criticalCandidates} critical and ${scan.summary.highCandidates} high candidate(s).`,
      { target: scan.rootPath }
    ),
    ...scan.guardChecks.map((check) =>
      createAuditEvent(scan.run?.runId ?? "unknown", "scopeguard", "guard.check", check.reason, {
        target: check.target,
        decision: check.decision
      })
    )
  ]);

  if (scan.run.jsonPath) {
    await writeRunJson(state.config, scan);
    console.log(color.green(`JSON run artifact written to ${scan.run.jsonPath}`));
  }
}

async function printAudit(state: CliState) {
  const lastScan = state.lastScan;
  if (!lastScan) {
    throw new Error("No scan yet. Run `scan` or `hunt` first.");
  }
  const events = await readAuditTail(state.config, lastScan.run?.runId ?? "unknown", 80);
  if (!events.length) {
    console.log(color.gray("No audit events found for last run."));
    return;
  }

  events.forEach((event) => {
    console.log(
      `${color.gray(event.timestamp)} ${color.bold(event.actor)} ${event.action} ${
        event.decision ? `[${event.decision}] ` : ""
      }${event.target ?? ""} ${color.gray(event.detail)}`
    );
  });
}

function createRunMetadata(
  command: string,
  rootPath: string,
  reportPath: string | undefined,
  jsonPath: string | undefined,
  state: CliState
): RunMetadata {
  const runId = createRunId("run");
  return {
    runId,
    organization: state.config.organization,
    policyProfile: state.config.policyProfile,
    operator: process.env.USER ?? process.env.USERNAME ?? "unknown",
    account: state.account,
    startedAt: new Date().toISOString(),
    finishedAt: new Date().toISOString(),
    command: `${command} ${rootPath}`,
    reportPath: reportPath ? path.resolve(reportPath) : undefined,
    jsonPath: jsonPath ? path.resolve(jsonPath) : undefined
  };
}

function finishRun(run: RunMetadata): RunMetadata {
  return {
    ...run,
    finishedAt: new Date().toISOString()
  };
}

function defaultReportPath(state: CliState) {
  const runId = state.lastScan?.run?.runId ?? createRunId("run");
  return path.join(state.config.reportDirectory, `${runId}.md`);
}

function defaultJsonPath(state: CliState) {
  return path.join(state.config.reportDirectory, `${createRunId("run")}.json`);
}

function parsePolicy(value: string | undefined) {
  if (value === "bug-bounty-safe" || value === "enterprise-audit" || value === "offline-only") {
    return value;
  }
  throw new Error("Policy must be one of: bug-bounty-safe, enterprise-audit, offline-only");
}

function requireScan(state: CliState): asserts state is CliState & { lastScan: ScanResult } {
  if (!state.lastScan) {
    throw new Error("No scan yet. Run `scan` or `hunt` first.");
  }
}

function printScope() {
  const engagement = createSampleEngagement();
  console.log(`\n${color.bold("Current safe-harbor scope template")}`);
  console.log(`Program: ${engagement.scope.program}`);
  console.log(`In scope: ${engagement.scope.inScope.map((asset) => asset.value).join(", ")}`);
  console.log(`Out of scope: ${engagement.scope.outOfScope.map((asset) => asset.value).join(", ")}`);
  console.log(`Max rate: ${engagement.policy.maxRequestsPerMinute}/min for approved live checks`);
  printSafeReminder();
}

function printEnterpriseStatus(state: CliState) {
  console.log(`\n${color.bold("Enterprise status")}`);
  console.log(`  org: ${state.config.organization}`);
  console.log(`  policy: ${state.config.policyProfile}`);
  console.log(`  audit: ${state.config.auditDirectory}`);
  console.log(`  reports: ${state.config.reportDirectory}`);
  console.log(
    `  account: ${
      state.account.connected ? color.green("connected") : color.yellow("not connected")
    } (${state.account.provider}/${state.account.source})`
  );
  if (state.account.email || state.account.organization) {
    console.log(
      `  identity: ${state.account.email ?? "unknown"} / ${state.account.organization ?? "unknown"}`
    );
  }
}

function splitCommand(line: string): string[] {
  const matches = line.match(/"([^"]*)"|'([^']*)'|[^\s]+/g) ?? [];
  return matches.map((part) => part.replace(/^["']|["']$/g, ""));
}

main().catch((error) => {
  console.error(color.red(error instanceof Error ? error.message : "P1Scan failed."));
  process.exitCode = 1;
});
