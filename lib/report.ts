import type { CodeFinding, ScanResult } from "./types";

export function renderMarkdownReport(scan: ScanResult): string {
  const topFindings = scan.findings.slice(0, 12);

  return `# P1Scan Candidate Report

Generated: ${new Date().toISOString()}
Root: \`${scan.rootPath}\`
Run ID: \`${scan.run?.runId ?? "not-recorded"}\`
Organization: ${scan.run?.organization ?? "not-recorded"}
Policy profile: \`${scan.run?.policyProfile ?? "not-recorded"}\`
Account: ${scan.run?.account.connected ? "connected" : "not connected"} (${scan.run?.account.provider ?? "unknown"})

## Summary

- Files scanned: ${scan.summary.scannedFiles}
- Lines scanned: ${scan.summary.scannedLines}
- Critical candidates: ${scan.summary.criticalCandidates}
- High candidates: ${scan.summary.highCandidates}
- Triage provider: ${scan.agentTriage.provider}
- Safe mode: ${scan.summary.safeMode ? "yes" : "no"}
- Human review required: yes

## Agent Triage

${scan.agentTriage.summary}

### Reasoning Focus

${list(scan.agentTriage.reasoningFocus)}

### Next Safe Searches

${list(scan.agentTriage.nextSearches)}

### Safety Notes

${list(scan.agentTriage.safetyNotes)}

## Top Candidates

${topFindings.map(renderFinding).join("\n\n")}

## Safe-Harbor Attestation

- This report is based on local static analysis and optional Claude Agent SDK planning-mode triage.
- No production writes, denial of service, credential use, persistence, lateral movement, or third-party data access were performed.
- Every candidate requires safe reproduction in local, fork, UAT, testnet, or owned-account environments before submission.
`;
}

function renderFinding(finding: CodeFinding, index: number): string {
  return `### ${index + 1}. ${finding.title}

- ID: \`${finding.id}\`
- Severity candidate: \`${finding.severity}\`
- Confidence: \`${finding.confidence}\`
- Lens: \`${finding.lens}\`
- Location: \`${finding.fileName}:${finding.line}\`

\`\`\`
${finding.snippet}
\`\`\`

**Root cause:** ${finding.rootCause}

**Counterfactual:** ${finding.counterfactual}

**Safe reproduction:** ${finding.safeReproduction}

**Remediation:** ${finding.remediation}

**Evidence standard:**

${list(finding.evidenceStandard)}

**Guardrails:**

${list(finding.guardrails)}`;
}

function list(items: string[]): string {
  if (!items.length) {
    return "- None";
  }

  return items.map((item) => `- ${item}`).join("\n");
}
