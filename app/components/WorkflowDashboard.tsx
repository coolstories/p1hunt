"use client";

import { useMemo, useState } from "react";
import clsx from "clsx";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  FileSearch,
  Fingerprint,
  FolderSearch,
  Gauge,
  LockKeyhole,
  Radar,
  ShieldCheck,
  Sparkles,
  UploadCloud
} from "lucide-react";
import type { AnalysisResult, CodeFinding, Engagement, ScanResult } from "@/lib/types";

interface WorkflowDashboardProps {
  engagement: Engagement;
  sampleCode: string;
  defaultRootPath: string;
}

export function WorkflowDashboard({
  engagement,
  sampleCode,
  defaultRootPath
}: WorkflowDashboardProps) {
  const [code, setCode] = useState(sampleCode);
  const [fileName, setFileName] = useState("routes/admin-export.ts");
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [rootPath, setRootPath] = useState(defaultRootPath);
  const [maxFiles, setMaxFiles] = useState(350);
  const [enableClaudeTriage, setEnableClaudeTriage] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const activeResult = scan ?? analysis;
  const findings = activeResult?.findings ?? engagement.findings;
  const hypotheses = activeResult?.hypotheses ?? engagement.hypotheses;
  const surfaces = activeResult?.surfaces ?? engagement.surfaces;
  const agentTriage = activeResult?.agentTriage;
  const metrics = useMemo(
    () => [
      {
        label: "Critical candidates",
        value: activeResult?.summary.criticalCandidates ?? 0,
        note: "Promote only with reproduced safe evidence"
      },
      {
        label: "Files scanned",
        value: "scannedFiles" in (activeResult?.summary ?? {})
          ? (activeResult as ScanResult).summary.scannedFiles
          : analysis
            ? 1
            : 0,
        note: "Repository scans obey file and byte limits"
      },
      {
        label: "Hypotheses",
        value: hypotheses.length,
        note: "Each includes stop conditions"
      }
    ],
    [activeResult, analysis, hypotheses.length]
  );

  async function runAnalysis() {
    setIsAnalyzing(true);
    setError(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code,
          fileName,
          scope: engagement.scope,
          policy: engagement.policy,
          enableClaudeTriage
        })
      });

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string };
        throw new Error(payload.error ?? "Analysis failed.");
      }

      setAnalysis((await response.json()) as AnalysisResult);
      setScan(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Analysis failed.");
    } finally {
      setIsAnalyzing(false);
    }
  }

  async function runRepositoryScan() {
    setIsScanning(true);
    setError(null);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rootPath,
          scope: engagement.scope,
          policy: engagement.policy,
          options: {
            rootPath,
            maxFiles,
            enableClaudeTriage
          }
        })
      });

      if (!response.ok) {
        const payload = (await response.json()) as { error?: string };
        throw new Error(payload.error ?? "Repository scan failed.");
      }

      setScan((await response.json()) as ScanResult);
      setAnalysis(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Repository scan failed.");
    } finally {
      setIsScanning(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <div className="hero-grid">
          <div>
            <div className="eyebrow">
              <ShieldCheck size={16} />
              Authorized critical vulnerability workflow
            </div>
            <h1>Find critical bugs without leaving safe harbor.</h1>
            <p>
              This app turns the spec into an operator dashboard: normalize scope,
              enforce safety gates, rank critical-impact surfaces, analyze local code,
              generate hypotheses, and prepare human-reviewed reports.
            </p>
            <div className="hero-actions">
              <button className="button primary" onClick={runAnalysis} disabled={isAnalyzing}>
                <FileSearch size={18} />
                {isAnalyzing ? "Analyzing safely..." : "Run safe local analysis"}
              </button>
              <button className="button" onClick={runRepositoryScan} disabled={isScanning}>
                <FolderSearch size={18} />
                {isScanning ? "Scanning repository..." : "Scan repository"}
              </button>
              <button className="button" onClick={() => setCode(sampleCode)}>
                <Sparkles size={18} />
                Load vulnerable sample
              </button>
            </div>
          </div>

          <aside className="hero-card">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">
                  <LockKeyhole size={19} />
                  Safety posture
                </h2>
                <p className="panel-subtitle">Every action is scoped before evidence is trusted.</p>
              </div>
              <span className="badge green">dry-run safe</span>
            </div>
            <div className="status-list">
              <StatusRow
                icon={<CheckCircle2 size={17} />}
                title="Scope normalized"
                text={`${engagement.scope.inScope.length} in-scope asset(s), ${engagement.scope.outOfScope.length} explicit exclusion(s).`}
              />
              <StatusRow
                icon={<Gauge size={17} />}
                title="Rate policy"
                text={`${engagement.policy.maxRequestsPerMinute} requests/min max for approved live checks.`}
              />
              <StatusRow
                icon={<Fingerprint size={17} />}
                title="Least-data evidence"
                text="Reports require redaction, owned data, synthetic data, or sandbox/fork traces."
              />
            </div>
          </aside>
        </div>
      </section>

      <section className="section grid three">
        {metrics.map((metric) => (
          <div className="metric-card" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
            <small>{metric.note}</small>
          </div>
        ))}
      </section>

      <section className="section grid two">
        <Panel
          icon={<FolderSearch size={20} />}
          title="Full repository scanner"
          subtitle="Scan a local authorized codebase with extension filters, max-file limits, secret redaction, and critical-impact ranking."
        >
          <div className="scanner">
            <input
              className="text-input"
              value={rootPath}
              onChange={(event) => setRootPath(event.target.value)}
              aria-label="Repository root path"
            />
            <div className="input-row">
              <input
                className="text-input"
                type="number"
                min={1}
                max={1500}
                value={maxFiles}
                onChange={(event) => setMaxFiles(Number(event.target.value))}
                aria-label="Maximum files"
              />
              <button className="button primary" onClick={runRepositoryScan} disabled={isScanning}>
                {isScanning ? "Scanning..." : "Run repository scan"}
              </button>
            </div>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={enableClaudeTriage}
                onChange={(event) => setEnableClaudeTriage(event.target.checked)}
              />
              <span>
                Enable Claude Agent SDK triage when credentials are configured. Runs in
                plan mode with tools disabled.
              </span>
            </label>
            {scan ? (
              <div className="status-list">
                <StatusRow
                  icon={<CheckCircle2 size={17} />}
                  title={`${scan.summary.scannedFiles} files scanned, ${scan.summary.skippedFiles} skipped`}
                  text={`${scan.summary.scannedLines} lines analyzed with ${scan.summary.criticalCandidates} critical and ${scan.summary.highCandidates} high candidate(s).`}
                />
                <StatusRow
                  icon={<Gauge size={17} />}
                  title="Search limits"
                  text={`${maxFiles} file cap; extension-filtered; ignored dependency/build directories.`}
                />
              </div>
            ) : null}
          </div>
        </Panel>

        <Panel
          icon={<Bot size={20} />}
          title="Claude agent triage"
          subtitle="Agent-assisted reasoning over top candidates, with no tools and no live target access."
        >
          {agentTriage ? (
            <div className="surface-list">
              <div className="surface-card">
                <div className="finding-top">
                  <h3>{agentTriage.provider}</h3>
                  <span className={clsx("badge", agentTriage.enabled ? "green" : "amber")}>
                    {agentTriage.enabled ? "enabled" : "fallback"}
                  </span>
                </div>
                <p>{agentTriage.summary}</p>
              </div>
              <RecommendationList title="Reasoning focus" items={agentTriage.reasoningFocus} />
              <RecommendationList title="Next searches" items={agentTriage.nextSearches} />
              <RecommendationList title="Safety notes" items={agentTriage.safetyNotes} />
            </div>
          ) : (
            <div className="empty">
              Run a scan to populate deterministic or Claude Agent SDK triage.
            </div>
          )}
        </Panel>
      </section>

      {scan ? (
        <section className="section grid two">
          <Panel
            icon={<FileSearch size={20} />}
            title="Scanned files"
            subtitle="Files with the strongest signals are listed first so you can jump into critical paths quickly."
          >
            <div className="file-list">
              {scan.scannedFiles
                .filter((file) => file.findingCount > 0)
                .slice(0, 18)
                .map((file) => (
                  <div className="file-row" key={file.path}>
                    <div>
                      <strong>{file.path}</strong>
                      <span>
                        {file.lines} lines · {file.targetClass}
                      </span>
                    </div>
                    <span className="badge red">
                      {file.criticalCount}C / {file.highCount}H
                    </span>
                  </div>
                ))}
              {scan.scannedFiles.every((file) => file.findingCount === 0) ? (
                <div className="empty">No finding-bearing files in this scan.</div>
              ) : null}
            </div>
          </Panel>

          <Panel
            icon={<AlertTriangle size={20} />}
            title="Skipped paths"
            subtitle="Skipped dependency/build directories and limit decisions are recorded for auditability."
          >
            {scan.skipped.length ? (
              <div className="file-list">
                {scan.skipped.slice(0, 18).map((item) => (
                  <div className="file-row" key={item}>
                    <div>
                      <strong>{item}</strong>
                      <span>Skipped by scanner policy or limit.</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty">No paths skipped.</div>
            )}
          </Panel>
        </section>
      ) : null}

      <section className="section grid two">
        <Panel
          icon={<Radar size={20} />}
          title="Workflow gates"
          subtitle="The workflow blocks unsafe promotion until each phase produces its artifact."
        >
          <div className="phase-stack">
            {engagement.phases.map((phase, index) => (
              <div className="phase-card" key={phase.id}>
                <span className="phase-index">{index + 1}</span>
                <div>
                  <h3>{phase.name}</h3>
                  <p>{phase.requiredOutput}</p>
                  <p>{phase.promotionGate}</p>
                </div>
                <span
                  className={clsx(
                    "badge",
                    phase.status === "complete" && "green",
                    phase.status === "active" && "amber",
                    phase.status === "blocked" && "red"
                  )}
                >
                  {phase.status}
                </span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          icon={<UploadCloud size={20} />}
          title="Local code scanner"
          subtitle="Paste in-scope source code or use the sample. The scanner only performs local static analysis."
        >
          <div className="scanner">
            <div className="input-row">
              <input
                className="text-input"
                value={fileName}
                onChange={(event) => setFileName(event.target.value)}
                aria-label="File name"
              />
              <button className="button primary" onClick={runAnalysis} disabled={isAnalyzing}>
                Analyze
              </button>
            </div>
            <textarea
              className="code-input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              spellCheck={false}
              aria-label="Code input"
            />
            {error ? <div className="badge red">{error}</div> : null}
            {analysis ? (
              <div className="status-list">
                <StatusRow
                  icon={<CheckCircle2 size={17} />}
                  title={`${analysis.summary.scannedLines} lines scanned as ${analysis.targetClass}`}
                  text={`${analysis.summary.criticalCandidates} critical and ${analysis.summary.highCandidates} high candidate(s) found in safe mode.`}
                />
                {analysis.guardChecks.map((check) => (
                  <StatusRow
                    key={`${check.action}-${check.target}`}
                    icon={check.decision === "allow" ? <CheckCircle2 size={17} /> : <AlertTriangle size={17} />}
                    title={`ScopeGuard ${check.decision}`}
                    text={check.reason}
                  />
                ))}
              </div>
            ) : null}
          </div>
        </Panel>
      </section>

      <section className="section grid two">
        <Panel
          icon={<AlertTriangle size={20} />}
          title="Critical and high candidates"
          subtitle="Findings remain candidates until reproduced in local, fork, UAT, or owned-account environments."
        >
          <FindingList findings={findings} />
        </Panel>

        <Panel
          icon={<ShieldCheck size={20} />}
          title="Impact surfaces"
          subtitle="Prioritized by program criticality, trust boundary, and safe testability."
        >
          {surfaces.length ? (
            <div className="surface-list">
              {surfaces.map((surface) => (
                <div className="surface-card" key={surface.id}>
                  <div className="finding-top">
                    <h3>{surface.title}</h3>
                    <span className="badge amber">P{surface.priority}</span>
                  </div>
                  <p>{surface.criticalityRationale}</p>
                  <p>
                    <strong>Boundary:</strong> {surface.trustBoundary}
                  </p>
                  <p>
                    <strong>Safe validation:</strong> {surface.safeValidationEnvironment}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">
              Run analysis to populate ranked impact surfaces for this engagement.
            </div>
          )}
        </Panel>
      </section>

      <section className="section grid two">
        <Panel
          icon={<FileSearch size={20} />}
          title="Safe hypotheses"
          subtitle="Each hypothesis includes assumptions, validation boundaries, evidence requirements, and stop conditions."
        >
          {hypotheses.length ? (
            <div className="hypothesis-list">
              {hypotheses.map((hypothesis) => (
                <div className="hypothesis-card" key={hypothesis.id}>
                  <div className="finding-top">
                    <h3>{hypothesis.id}</h3>
                    <span className="badge">{hypothesis.status}</span>
                  </div>
                  <p>{hypothesis.claim}</p>
                  <p>
                    <strong>Safe plan:</strong> {hypothesis.safeValidationPlan.environment};
                    {" "}{hypothesis.safeValidationPlan.dataHandling}.
                  </p>
                  <p>
                    <strong>Stop:</strong> {hypothesis.stopConditions.join("; ")}.
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty">
              Candidate hypotheses will appear after safe local analysis finds a signal.
            </div>
          )}
        </Panel>

        <Panel
          icon={<Sparkles size={20} />}
          title="Report readiness"
          subtitle="The final package is designed for human review before any bug bounty submission."
        >
          <div className="status-list">
            <StatusRow
              icon={<CheckCircle2 size={17} />}
              title="Counterfactual severity"
              text="Every promoted finding must explain what changed because of the bug and map that delta to the program taxonomy."
            />
            <StatusRow
              icon={<CheckCircle2 size={17} />}
              title="Reproducible evidence"
              text="Triagers get minimal safe steps, local/fork/UAT artifacts, and redacted proof."
            />
            <StatusRow
              icon={<CheckCircle2 size={17} />}
              title="Human review required"
              text="No report is auto-submitted. Scope, impact, wording, and channel require a human approval gate."
            />
          </div>
        </Panel>
      </section>

      <p className="footer-note">
        Built for authorized bug bounty work only. The app favors local source analysis,
        sandboxed validation, and least-data reporting over live target interaction.
      </p>
    </main>
  );
}

function Panel({
  icon,
  title,
  subtitle,
  children
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <h2 className="panel-title">
            {icon}
            {title}
          </h2>
          <p className="panel-subtitle">{subtitle}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

function StatusRow({
  icon,
  title,
  text
}: {
  icon: React.ReactNode;
  title: string;
  text: string;
}) {
  return (
    <div className="status-row">
      <span className="icon-pill">{icon}</span>
      <div>
        <strong>{title}</strong>
        <span>{text}</span>
      </div>
    </div>
  );
}

function RecommendationList({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="detail-box">
      <strong>{title}</strong>
      {items.length ? (
        <ul>
          {items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : (
        <p>No recommendations returned.</p>
      )}
    </div>
  );
}

function FindingList({ findings }: { findings: CodeFinding[] }) {
  if (!findings.length) {
    return (
      <div className="empty">
        No critical or high candidates yet. Add an in-scope source file and run safe
        local analysis to generate evidence-backed hypotheses.
      </div>
    );
  }

  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <article className="finding-card" key={finding.id}>
          <div className="finding-top">
            <div>
              <h3>{finding.title}</h3>
              <div className="finding-meta">
                {finding.fileName}:{finding.line} · {finding.lens} · {finding.confidence} confidence
              </div>
            </div>
            <span
              className={clsx(
                "badge",
                finding.severity === "critical" ? "red" : "amber"
              )}
            >
              {finding.severity}
            </span>
          </div>
          <pre className="snippet">{finding.snippet}</pre>
          <div className="detail-grid">
            <DetailBox title="Root cause" text={finding.rootCause} />
            <DetailBox title="Safe reproduction" text={finding.safeReproduction} />
            <DetailBox title="Counterfactual" text={finding.counterfactual} />
            <DetailBox title="Remediation" text={finding.remediation} />
            <div className="detail-box">
              <strong>Evidence standard</strong>
              <ul>
                {finding.evidenceStandard.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
            <div className="detail-box">
              <strong>Guardrails</strong>
              <ul>
                {finding.guardrails.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function DetailBox({ title, text }: { title: string; text: string }) {
  return (
    <div className="detail-box">
      <strong>{title}</strong>
      <p>{text}</p>
    </div>
  );
}
