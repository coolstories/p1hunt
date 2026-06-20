import type { AgentTriage, CodeFinding, Scope } from "./types";

interface ClaudeTriageInput {
  enabled: boolean;
  findings: CodeFinding[];
  scope: Scope;
  rootPath: string;
}

interface ParsedClaudeTriage {
  summary?: string;
  reasoningFocus?: string[];
  promotedFindingIds?: string[];
  demotedFindingIds?: string[];
  nextSearches?: string[];
  safetyNotes?: string[];
}

export async function runClaudeTriage(input: ClaudeTriageInput): Promise<AgentTriage> {
  if (!input.enabled) {
    return deterministicTriage(input.findings, "Claude Agent SDK triage is disabled.");
  }

  if (!process.env.ANTHROPIC_API_KEY && !process.env.CLAUDE_CODE_USE_BEDROCK && !process.env.CLAUDE_CODE_USE_VERTEX) {
    return deterministicTriage(
      input.findings,
      "Claude Agent SDK triage was requested, but no Anthropic/Bedrock/Vertex credentials were detected."
    );
  }

  try {
    const { query } = await import("@anthropic-ai/claude-agent-sdk");
    const prompt = buildTriagePrompt(input);
    let text = "";

    for await (const message of query({
      prompt,
      options: {
        cwd: input.rootPath,
        maxTurns: 1,
        model: process.env.CLAUDE_SCANNER_MODEL ?? "sonnet",
        permissionMode: "plan",
        tools: [],
        disallowedTools: [
          "Bash",
          "Edit",
          "Write",
          "WebFetch",
          "WebSearch",
          "NotebookEdit",
          "Task"
        ],
        canUseTool: async () => ({
          behavior: "deny",
          message: "This scanner allows Claude triage only in no-tool planning mode."
        })
      }
    })) {
      text += extractText(message);
    }

    const parsed = parseJson(text);
    return {
      provider: "claude-agent-sdk",
      enabled: true,
      summary: parsed.summary ?? "Claude completed triage but did not provide a summary.",
      reasoningFocus: parsed.reasoningFocus ?? [],
      promotedFindingIds: parsed.promotedFindingIds ?? [],
      demotedFindingIds: parsed.demotedFindingIds ?? [],
      nextSearches: parsed.nextSearches ?? [],
      safetyNotes: parsed.safetyNotes ?? [
        "Claude triage ran in plan mode with tools disabled."
      ]
    };
  } catch (error) {
    return deterministicTriage(
      input.findings,
      `Claude Agent SDK triage failed: ${
        error instanceof Error ? error.message : "unknown error"
      }`
    );
  }
}

function buildTriagePrompt(input: ClaudeTriageInput): string {
  const findings = input.findings.map((finding) => ({
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    lens: finding.lens,
    fileName: finding.fileName,
    line: finding.line,
    snippet: finding.snippet,
    rootCause: finding.rootCause,
    counterfactual: finding.counterfactual
  }));

  return `You are a safe-harbor bug bounty triage agent.

Rules:
- Do not request or describe destructive validation.
- Do not suggest live exploitation, production writes, denial of service, persistence, credential attacks, or data exfiltration.
- Reason only over the provided local static findings.
- Promote candidates only if they plausibly map to critical impact and have a safe local/fork/UAT validation path.
- Demote noisy findings if reachability, impact, or control assumptions look weak.

Program: ${input.scope.program}
Safe harbor: ${input.scope.safeHarborText}
Critical taxonomy: ${input.scope.severityTaxonomy.P1 ?? "Use program-provided critical impact only."}

Return strict JSON with:
{
  "summary": "short triage summary",
  "reasoningFocus": ["what a researcher should verify next"],
  "promotedFindingIds": ["finding ids that deserve priority"],
  "demotedFindingIds": ["finding ids likely noisy or lower impact"],
  "nextSearches": ["safe code searches to run locally"],
  "safetyNotes": ["scope and least-data reminders"]
}

Findings:
${JSON.stringify(findings, null, 2)}
`;
}

function deterministicTriage(findings: CodeFinding[], reason: string): AgentTriage {
  const promotedFindingIds = findings
    .filter((finding) => finding.severity === "critical")
    .slice(0, 12)
    .map((finding) => finding.id);

  return {
    provider: "deterministic-fallback",
    enabled: false,
    summary: `${reason} Deterministic ranking prioritized critical severity, higher confidence, and authorization/asset-custody/trusted-execution lenses.`,
    reasoningFocus: [
      "Verify reachability from an untrusted or lower-privileged actor.",
      "Trace callers and upstream middleware for authorization and validation.",
      "Confirm the impact with local, fork, UAT, or owned-account evidence only.",
      "Demote findings when compensating controls remove the critical impact."
    ],
    promotedFindingIds,
    demotedFindingIds: findings
      .filter((finding) => finding.confidence === "low")
      .slice(0, 12)
      .map((finding) => finding.id),
    nextSearches: [
      "Search callers of matched functions and routes.",
      "Search object ownership checks around every direct object lookup.",
      "Search middleware order and auth bypass exceptions.",
      "Search tests for negative cross-tenant and privilege-boundary cases."
    ],
    safetyNotes: [
      "No live target interaction was performed.",
      "Do not use discovered credentials; report and request guidance.",
      "Keep evidence synthetic, owned, redacted, aggregate, or sandbox/fork-only."
    ]
  };
}

function extractText(message: unknown): string {
  const maybeMessage = message as {
    type?: string;
    message?: { content?: Array<{ type?: string; text?: string }> };
    result?: string;
  };

  if (typeof maybeMessage.result === "string") {
    return maybeMessage.result;
  }

  if (maybeMessage.type === "assistant") {
    return (
      maybeMessage.message?.content
        ?.map((block) => (block.type === "text" ? block.text ?? "" : ""))
        .join("") ?? ""
    );
  }

  return "";
}

function parseJson(text: string): ParsedClaudeTriage {
  const match = text.match(/\{[\s\S]*\}/);
  if (!match) {
    return { summary: text.trim().slice(0, 500) };
  }

  try {
    return JSON.parse(match[0]) as ParsedClaudeTriage;
  } catch {
    return { summary: text.trim().slice(0, 500) };
  }
}
