import type { CodeFinding, ScanResult } from "../lib/types";

const supportsColor = process.stdout.isTTY;

export const color = {
  cyan: (text: string) => paint(text, "36"),
  green: (text: string) => paint(text, "32"),
  yellow: (text: string) => paint(text, "33"),
  red: (text: string) => paint(text, "31"),
  gray: (text: string) => paint(text, "90"),
  bold: (text: string) => paint(text, "1"),
  dim: (text: string) => paint(text, "2")
};

export function banner() {
  console.log(
    color.cyan(`
╔══════════════════════════════════════════════════════════════╗
║ P1Scan                                                       ║
║ Autonomous safe-harbor terminal hunter for P1 candidates     ║
╚══════════════════════════════════════════════════════════════╝
`)
  );
  console.log(
    [
      color.bold("Mode:"),
      "authorized local code search, Claude Agent SDK triage, no live exploitation.",
      "\nType",
      color.cyan("help"),
      "for commands."
    ].join(" ")
  );
}

export function printHelp() {
  console.log(`
Commands
  init                                      Create .p1scan enterprise config
  status                                    Show account, policy, audit, and report status
  config show                               Show enterprise config
  config set <key> <value>                  Update supported config keys
  scan [path] [--agent] [--max-files N]     Run one repository scan
       [--report file] [--json file] [--policy profile]
  hunt [path] [--agent] [--rounds N]        Autonomous P1 hunt loop
       [--report file] [--json file] [--policy profile]
  findings                                  Show top candidates from last scan
  agent                                     Show Claude/fallback triage from last scan
  audit                                     Show audit events for last run
  report [file]                             Export markdown report
  scope                                     Show safety policy summary
  help                                      Show this help
  quit                                      Exit

Examples
  scan ./target --agent --max-files 800
  hunt ../program-repo --rounds 4 --agent
  hunt ./target --rounds 3 --report p1scan-report.md --json p1scan-run.json
  config set organization "Acme Security"
  report p1scan-report.md
`);
}

export function printScanSummary(scan: ScanResult) {
  console.log(
    [
      "\n",
      color.bold("Scan complete"),
      " ",
      color.gray(scan.rootPath),
      "\n",
      `  files: ${scan.summary.scannedFiles}/${scan.summary.totalFiles}`,
      `  lines: ${scan.summary.scannedLines}`,
      `  critical: ${color.red(String(scan.summary.criticalCandidates))}`,
      `  high: ${color.yellow(String(scan.summary.highCandidates))}`,
      `  triage: ${scan.agentTriage.provider}`
    ].join("")
  );
}

export function printFindings(findings: CodeFinding[], limit = 10) {
  if (!findings.length) {
    console.log(color.gray("No candidates found yet."));
    return;
  }

  findings.slice(0, limit).forEach((finding, index) => {
    const severity =
      finding.severity === "critical"
        ? color.red(finding.severity.toUpperCase())
        : color.yellow(finding.severity.toUpperCase());

    console.log(`
${color.bold(`${index + 1}. ${finding.title}`)} ${severity} ${color.gray(finding.confidence)}
   ${finding.fileName}:${finding.line}
   lens: ${finding.lens}
   id: ${finding.id}
   ${color.gray(finding.snippet)}
`);
  });
}

export function printTriage(scan: ScanResult) {
  const triage = scan.agentTriage;
  console.log(`\n${color.bold("Agent triage")} ${color.gray(triage.provider)}`);
  console.log(triage.summary);
  printList("Reasoning focus", triage.reasoningFocus);
  printList("Next safe searches", triage.nextSearches);
  printList("Safety notes", triage.safetyNotes);
}

export function printHuntRound(round: number, frame: string) {
  console.log(`\n${color.cyan(`Round ${round}`)} ${color.bold(frame)}`);
}

export function printSafeReminder() {
  console.log(
    color.gray(
      "Safe-harbor reminder: local/fork/UAT/owned-account validation only; no production writes, DoS, credential use, or third-party data access."
    )
  );
}

function printList(title: string, items: string[]) {
  console.log(`\n${color.bold(title)}`);
  if (!items.length) {
    console.log(`  ${color.gray("None")}`);
    return;
  }
  items.forEach((item) => console.log(`  - ${item}`));
}

function paint(text: string, code: string): string {
  if (!supportsColor) {
    return text;
  }
  return `\u001b[${code}m${text}\u001b[0m`;
}
