import { readdir, readFile, stat } from "fs/promises";
import path from "path";
import { analyzeCode } from "./analyzer";
import { runClaudeTriage } from "./claude-agent";
import type {
  AgentTriage,
  CodeFinding,
  GuardCheck,
  Hypothesis,
  ImpactSurface,
  ScanOptions,
  ScanResult,
  ScannedFile,
  Scope,
  ScopeGuardPolicy
} from "./types";

const defaultExtensions = [
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".py",
  ".go",
  ".java",
  ".kt",
  ".rb",
  ".php",
  ".cs",
  ".rs",
  ".sol",
  ".swift",
  ".yml",
  ".yaml",
  ".json",
  ".tf",
  ".toml",
  ".xml",
  ".env",
  ".properties",
  ".conf"
];

const defaultIgnores = [
  "node_modules",
  ".git",
  ".next",
  "dist",
  "build",
  "coverage",
  ".venv",
  "vendor",
  "target",
  ".turbo",
  ".cache",
  ".p1scan"
];

export function getDefaultScanOptions(rootPath = process.cwd()): ScanOptions {
  return {
    rootPath,
    maxFiles: 350,
    maxBytesPerFile: 260_000,
    includeExtensions: defaultExtensions,
    ignoreDirectories: defaultIgnores,
    enableClaudeTriage: false
  };
}

export async function scanRepository(
  options: ScanOptions,
  policy: ScopeGuardPolicy,
  scope: Scope
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const rootPath = path.resolve(options.rootPath);
  const discovered = await discoverFiles(rootPath, options);
  const findings: CodeFinding[] = [];
  const hypotheses: Hypothesis[] = [];
  const surfaces: ImpactSurface[] = [];
  const guardChecks: GuardCheck[] = [];
  const scannedFiles: ScannedFile[] = [];
  const skipped = [...discovered.skipped];
  let scannedLines = 0;

  for (const filePath of discovered.files) {
    try {
      const fileStat = await stat(filePath);
      if (fileStat.size > options.maxBytesPerFile) {
        skipped.push(`${path.relative(rootPath, filePath)}: over maxBytesPerFile`);
        continue;
      }

      const code = await readFile(filePath, "utf8");
      const relativePath = path.relative(rootPath, filePath);
      const result = analyzeCode({
        code,
        fileName: relativePath,
        policy
      });

      findings.push(...result.findings);
      hypotheses.push(...result.hypotheses);
      surfaces.push(...result.surfaces);
      guardChecks.push(...result.guardChecks);
      scannedLines += result.summary.scannedLines;
      scannedFiles.push({
        path: relativePath,
        bytes: fileStat.size,
        lines: result.summary.scannedLines,
        targetClass: result.targetClass,
        findingCount: result.findings.length,
        criticalCount: result.summary.criticalCandidates,
        highCount: result.summary.highCandidates
      });
    } catch (error) {
      skipped.push(
        `${path.relative(rootPath, filePath)}: ${
          error instanceof Error ? error.message : "could not read file"
        }`
      );
    }
  }

  const rankedFindings = rankFindings(findings);
  const agentTriage = await runClaudeTriage({
    enabled: options.enableClaudeTriage,
    findings: rankedFindings.slice(0, 25),
    scope,
    rootPath
  });

  return {
    rootPath,
    startedAt,
    finishedAt: new Date().toISOString(),
    scannedFiles,
    skipped,
    findings: rankedFindings,
    hypotheses: hypotheses.slice(0, 100),
    surfaces: dedupeSurfaces(surfaces).slice(0, 40),
    guardChecks: dedupeGuardChecks(guardChecks),
    agentTriage,
    summary: {
      totalFiles: discovered.totalFiles,
      scannedFiles: scannedFiles.length,
      skippedFiles: skipped.length,
      scannedLines,
      criticalCandidates: rankedFindings.filter((finding) => finding.severity === "critical")
        .length,
      highCandidates: rankedFindings.filter((finding) => finding.severity === "high").length,
      safeMode: guardChecks.every((check) => check.decision === "allow")
    }
  };
}

async function discoverFiles(rootPath: string, options: ScanOptions) {
  const files: string[] = [];
  const skipped: string[] = [];
  let totalFiles = 0;

  async function walk(directory: string) {
    if (files.length >= options.maxFiles) {
      return;
    }

    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= options.maxFiles) {
        skipped.push("maxFiles reached");
        return;
      }

      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        if (options.ignoreDirectories.includes(entry.name)) {
          skipped.push(`${path.relative(rootPath, absolutePath)}: ignored directory`);
          continue;
        }
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }

      totalFiles += 1;
      const ext = path.extname(entry.name).toLowerCase();
      const include =
        options.includeExtensions.includes(ext) ||
        entry.name === "Dockerfile" ||
        entry.name.startsWith(".env");

      if (!include) {
        continue;
      }

      files.push(absolutePath);
    }
  }

  await walk(rootPath);
  return { files, skipped, totalFiles };
}

function rankFindings(findings: CodeFinding[]): CodeFinding[] {
  const severityWeight: Record<CodeFinding["severity"], number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };
  const confidenceWeight: Record<CodeFinding["confidence"], number> = {
    high: 3,
    medium: 2,
    low: 1
  };

  return [...findings].sort((left, right) => {
    const leftScore = severityWeight[left.severity] * 10 + confidenceWeight[left.confidence];
    const rightScore = severityWeight[right.severity] * 10 + confidenceWeight[right.confidence];
    return rightScore - leftScore || left.fileName.localeCompare(right.fileName);
  });
}

function dedupeSurfaces(surfaces: ImpactSurface[]): ImpactSurface[] {
  const seen = new Set<string>();
  return surfaces.filter((surface) => {
    const key = `${surface.lens}:${surface.targetAsset}:${surface.title}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function dedupeGuardChecks(checks: GuardCheck[]): GuardCheck[] {
  const seen = new Set<string>();
  return checks.filter((check) => {
    const key = `${check.action}:${check.target}:${check.decision}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export function fallbackTriage(findings: CodeFinding[]): AgentTriage {
  const criticalIds = findings
    .filter((finding) => finding.severity === "critical")
    .slice(0, 10)
    .map((finding) => finding.id);

  return {
    provider: "deterministic-fallback",
    enabled: false,
    summary:
      "Claude Agent SDK triage is disabled. Deterministic scanner ranked candidates by severity, confidence, and critical-impact lens.",
    reasoningFocus: [
      "Confirm reachability from an untrusted or lower-privileged actor.",
      "Check whether an upstream authorization, validation, or compensating control removes impact.",
      "Require local, fork, UAT, or owned-account reproduction before promotion."
    ],
    promotedFindingIds: criticalIds,
    demotedFindingIds: [],
    nextSearches: [
      "Search for callers of each matched function.",
      "Search for authorization middleware and object ownership checks around each route.",
      "Search tests for negative cross-tenant and privilege-boundary cases."
    ],
    safetyNotes: [
      "No live exploitation was performed.",
      "No destructive validation is recommended.",
      "Evidence should remain least-data and redacted."
    ]
  };
}
