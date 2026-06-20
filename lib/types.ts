export type EngagementStatus =
  | "READY"
  | "BLOCKED_NEEDS_HUMAN_SCOPE_DECISION"
  | "TESTING"
  | "REPORT_READY";

export type PhaseId =
  | "intake"
  | "safety"
  | "acquisition"
  | "mapping"
  | "hypothesis"
  | "testing"
  | "verification"
  | "reporting";

export type CriticalLens =
  | "authorization-boundary"
  | "asset-custody"
  | "trusted-execution"
  | "confidentiality"
  | "availability-if-allowed"
  | "business-logic";

export type TargetClass =
  | "WEB_API"
  | "SOURCE_REPO"
  | "MOBILE_APP"
  | "EVM_CONTRACT"
  | "CLOUD_INFRA"
  | "SUPPLY_CHAIN"
  | "OTHER";

export type GuardDecision = "allow" | "deny";

export type PolicyProfile = "bug-bounty-safe" | "enterprise-audit" | "offline-only";

export interface Asset {
  id: string;
  label: string;
  type: "domain" | "repo" | "package" | "contract" | "apk" | "host" | "other";
  value: string;
  environment: "local" | "fork" | "testnet" | "uat" | "production" | "unknown";
}

export interface Scope {
  program: string;
  platform: string;
  disclosureChannel: string;
  safeHarborText: string;
  severityTaxonomy: Record<string, string>;
  inScope: Asset[];
  outOfScope: Asset[];
  ambiguous: Asset[];
  rules: string[];
  rateLimit: string;
}

export interface ScopeGuardPolicy {
  allowlist: string[];
  denylist: string[];
  sandboxEnvironments: Asset["environment"][];
  allowedHttpMethods: string[];
  maxRequestsPerMinute: number;
  unattendedMode: boolean;
  evidenceMode: "least-data";
}

export interface GuardCheck {
  action: string;
  target: string;
  decision: GuardDecision;
  reason: string;
}

export interface WorkflowPhase {
  id: PhaseId;
  name: string;
  requiredOutput: string;
  promotionGate: string;
  status: "complete" | "active" | "blocked" | "pending";
}

export interface ImpactSurface {
  id: string;
  title: string;
  lens: CriticalLens;
  targetAsset: string;
  trustBoundary: string;
  safeValidationEnvironment: string;
  criticalityRationale: string;
  priority: number;
}

export interface Hypothesis {
  id: string;
  claim: string;
  lens: CriticalLens;
  targetAssets: string[];
  assumptions: string[];
  safeValidationPlan: {
    environment: string;
    maxContact: string;
    dataHandling: string;
  };
  stopConditions: string[];
  evidenceRequired: string[];
  status: "OPEN" | "TESTING" | "FALSIFIED" | "CANDIDATE" | "CONFIRMED";
}

export interface CodeFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  lens: CriticalLens;
  fileName: string;
  line: number;
  snippet: string;
  rootCause: string;
  safeReproduction: string;
  counterfactual: string;
  remediation: string;
  evidenceStandard: string[];
  guardrails: string[];
}

export interface AgentTriage {
  provider: "claude-agent-sdk" | "deterministic-fallback";
  enabled: boolean;
  summary: string;
  reasoningFocus: string[];
  promotedFindingIds: string[];
  demotedFindingIds: string[];
  nextSearches: string[];
  safetyNotes: string[];
}

export interface AnalysisResult {
  targetClass: TargetClass;
  findings: CodeFinding[];
  hypotheses: Hypothesis[];
  surfaces: ImpactSurface[];
  guardChecks: GuardCheck[];
  agentTriage?: AgentTriage;
  summary: {
    scannedLines: number;
    criticalCandidates: number;
    highCandidates: number;
    safeMode: boolean;
  };
}

export interface ScanOptions {
  rootPath: string;
  maxFiles: number;
  maxBytesPerFile: number;
  includeExtensions: string[];
  ignoreDirectories: string[];
  enableClaudeTriage: boolean;
  policyProfile?: PolicyProfile;
}

export interface AccountStatus {
  connected: boolean;
  provider: "anthropic" | "bedrock" | "vertex" | "gateway" | "unknown";
  source: "api-key" | "oauth" | "cloud" | "environment" | "none";
  email?: string;
  organization?: string;
  subscriptionType?: string;
  detail: string;
}

export interface EnterpriseConfig {
  version: 1;
  organization: string;
  policyProfile: PolicyProfile;
  defaultRootPath: string;
  maxFiles: number;
  maxBytesPerFile: number;
  enableClaudeTriage: boolean;
  requireHumanReview: boolean;
  auditDirectory: string;
  reportDirectory: string;
}

export interface AuditEvent {
  id: string;
  runId: string;
  timestamp: string;
  actor: "operator" | "scanner" | "claude-agent-sdk" | "scopeguard";
  action: string;
  target?: string;
  decision?: GuardDecision;
  detail: string;
}

export interface RunMetadata {
  runId: string;
  organization: string;
  policyProfile: PolicyProfile;
  operator: string;
  account: AccountStatus;
  startedAt: string;
  finishedAt: string;
  command: string;
  reportPath?: string;
  jsonPath?: string;
}

export interface ScannedFile {
  path: string;
  bytes: number;
  lines: number;
  targetClass: TargetClass;
  findingCount: number;
  criticalCount: number;
  highCount: number;
}

export interface ScanResult {
  run?: RunMetadata;
  rootPath: string;
  startedAt: string;
  finishedAt: string;
  scannedFiles: ScannedFile[];
  skipped: string[];
  findings: CodeFinding[];
  hypotheses: Hypothesis[];
  surfaces: ImpactSurface[];
  guardChecks: GuardCheck[];
  agentTriage: AgentTriage;
  summary: {
    totalFiles: number;
    scannedFiles: number;
    skippedFiles: number;
    scannedLines: number;
    criticalCandidates: number;
    highCandidates: number;
    safeMode: boolean;
  };
}

export interface Engagement {
  id: string;
  status: EngagementStatus;
  scope: Scope;
  policy: ScopeGuardPolicy;
  phases: WorkflowPhase[];
  surfaces: ImpactSurface[];
  hypotheses: Hypothesis[];
  findings: CodeFinding[];
}
