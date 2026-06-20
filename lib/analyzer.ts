import type {
  AnalysisResult,
  CodeFinding,
  CriticalLens,
  GuardCheck,
  Hypothesis,
  ImpactSurface,
  TargetClass
} from "./types";
import { evaluateAction } from "./scopeguard";
import type { ScopeGuardPolicy } from "./types";

export interface AnalyzeCodeInput {
  code: string;
  fileName: string;
  policy: ScopeGuardPolicy;
}

interface Rule {
  id: string;
  title: string;
  severity: CodeFinding["severity"];
  confidence: CodeFinding["confidence"];
  lens: CriticalLens;
  match: RegExp;
  rootCause: string;
  safeReproduction: string;
  counterfactual: string;
  remediation: string;
}

const rules: Rule[] = [
  {
    id: "AUTHZ_BYPASS",
    title: "Authorization decision may be bypassed or fail open",
    severity: "critical",
    confidence: "medium",
    lens: "authorization-boundary",
    match:
      /(return\s+true\s*;?\s*\/\/\s*(todo|temporary|debug|fixme)|if\s*\([^)]*(admin|owner|role|permission)[^)]*\)\s*{\s*return\s+true)/i,
    rootCause:
      "Authorization-sensitive code appears to return success without a complete policy check.",
    safeReproduction:
      "Write a local unit test with two owned synthetic users: one authorized and one unauthorized. Assert that the unauthorized actor cannot access the protected object.",
    counterfactual:
      "Without this bug, an unrelated or lower-privileged actor should be denied. With it, the actor may cross an authorization boundary.",
    remediation:
      "Centralize authorization checks, deny by default, require object ownership or role membership, and add regression tests for negative cases."
  },
  {
    id: "SECRET_IN_SOURCE",
    title: "Sensitive credential appears hardcoded in source",
    severity: "critical",
    confidence: "high",
    lens: "trusted-execution",
    match:
      /((private[_-]?key|api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_./+=-]{20,}["'])/i,
    rootCause:
      "A credential-like value appears to be embedded in source code, which can undermine account, signing, deployment, or service boundaries.",
    safeReproduction:
      "Do not use the credential. Confirm only that the value is present in the in-scope artifact, redact it, and ask the program whether additional validation is desired.",
    counterfactual:
      "Without this bug, the secret should be stored outside source and unavailable to readers. With it, anyone with artifact access may gain the secret's privileges.",
    remediation:
      "Revoke and rotate the credential, move secrets to a managed secret store, and add secret scanning to CI."
  },
  {
    id: "COMMAND_INJECTION",
    title: "User-controlled input may reach command execution",
    severity: "critical",
    confidence: "medium",
    lens: "trusted-execution",
    match:
      /(exec|execSync|spawn|spawnSync|system|popen|ProcessBuilder)\s*\([^;\n]*(req\.|request\.|params|query|body|argv|input)/i,
    rootCause:
      "Untrusted input appears to flow into operating-system command execution.",
    safeReproduction:
      "Use a local harness with benign synthetic input to prove that command arguments are constructed from user-controlled data. Do not run destructive commands.",
    counterfactual:
      "Without this bug, user input should not influence command execution. With it, a remote or lower-privileged actor may affect trusted execution.",
    remediation:
      "Avoid shell execution, use fixed argument arrays, validate allowlisted values, and isolate any required process execution."
  },
  {
    id: "SQL_INJECTION",
    title: "Query construction may allow injection into data access",
    severity: "high",
    confidence: "medium",
    lens: "confidentiality",
    match:
      /((select|update|delete|insert)\s+[^;\n]*\$\{[^}]+}|query\s*\([^;\n]*(\+|concat\()[^;\n]*(req\.|request\.|params|query|body))/i,
    rootCause:
      "Database queries appear to be assembled with string interpolation or concatenation from untrusted input.",
    safeReproduction:
      "Use a local database fixture with synthetic records to show that parameterized and unparameterized behavior differ.",
    counterfactual:
      "Without this bug, input is treated as data. With it, an actor may alter query meaning and cross confidentiality or integrity boundaries.",
    remediation:
      "Use parameterized queries or ORM bind variables, enforce query builders, and test unsafe metacharacters against local fixtures."
  },
  {
    id: "SSRF",
    title: "User-controlled URL may be fetched by trusted server",
    severity: "high",
    confidence: "medium",
    lens: "authorization-boundary",
    match:
      /(fetch|axios\.get|axios\.post|request|got)\s*\([^;\n]*(req\.|request\.|params|query|body|url)/i,
    rootCause:
      "A server-side network client appears to accept a user-controlled destination.",
    safeReproduction:
      "Use an owned local listener or mock service in a local environment to show that the destination is attacker-controlled.",
    counterfactual:
      "Without this bug, server-side requests should only reach approved destinations. With it, an actor may cross network trust boundaries.",
    remediation:
      "Require a strict destination allowlist, block private/internal ranges, disable redirects unless needed, and validate parsed URLs."
  },
  {
    id: "PATH_TRAVERSAL",
    title: "User-controlled path may reach file access",
    severity: "high",
    confidence: "medium",
    lens: "confidentiality",
    match:
      /(readFile|readFileSync|createReadStream|sendFile|open)\s*\([^;\n]*(req\.|request\.|params|query|body|filename|path)/i,
    rootCause:
      "A file path appears to include user-controlled input without clear normalization and containment.",
    safeReproduction:
      "Create a local fixture directory with synthetic files and prove whether path resolution can leave the intended directory.",
    counterfactual:
      "Without this bug, users can access only intended files. With it, they may read sensitive local files or tenant data.",
    remediation:
      "Resolve paths against a fixed base directory, reject traversal after normalization, and use opaque file identifiers."
  },
  {
    id: "PROTOTYPE_POLLUTION",
    title: "Dynamic object merge may allow prototype pollution",
    severity: "high",
    confidence: "low",
    lens: "business-logic",
    match:
      /(merge|assign|set)\s*\([^;\n]*(req\.|request\.|body|params|query)|(__proto__|constructor|prototype)\s*\]/i,
    rootCause:
      "Untrusted object keys may be merged into application objects without blocking prototype-related keys.",
    safeReproduction:
      "Use a local unit test with synthetic keys to show whether object prototypes or security-relevant defaults can change.",
    counterfactual:
      "Without this bug, request keys affect only intended data. With it, an actor may alter shared defaults or authorization logic.",
    remediation:
      "Reject prototype-related keys, use safe deep-merge libraries, create null-prototype objects, and validate schemas at trust boundaries."
  },
  {
    id: "JWT_DECODE_WITHOUT_VERIFY",
    title: "JWT may be decoded without signature verification",
    severity: "critical",
    confidence: "medium",
    lens: "authorization-boundary",
    match: /(jwt\.decode|decodeJwt|verify\s*:\s*false|algorithms\s*:\s*\[\s*["']none["'])/i,
    rootCause:
      "Token handling appears to parse or accept JWTs without enforcing trusted signature verification.",
    safeReproduction:
      "Use a local unit test with synthetic tokens to prove whether unsigned or tampered tokens are accepted. Do not target production sessions.",
    counterfactual:
      "Without this bug, only tokens signed by the trusted issuer should authorize access. With it, an actor may mint or alter identity claims.",
    remediation:
      "Require issuer, audience, expiry, and signature verification with an allowlisted algorithm and centralized auth middleware."
  },
  {
    id: "MASS_ASSIGNMENT_PRIVILEGE",
    title: "Mass assignment may let users set privileged fields",
    severity: "critical",
    confidence: "medium",
    lens: "authorization-boundary",
    match:
      /(create|update|insert|save)\s*\([^;\n]*(req\.body|request\.body|body)[^;\n]*(role|admin|isAdmin|owner|permissions|balance|tenantId|orgId)/i,
    rootCause:
      "Request-controlled objects appear to be written into privileged fields without an explicit allowlist.",
    safeReproduction:
      "Use a local or UAT owned account to submit synthetic privileged fields and confirm whether they are ignored or persisted.",
    counterfactual:
      "Without this bug, users can update only intended profile fields. With it, they may change privileges, tenant ownership, or protected business state.",
    remediation:
      "Use DTO/schema allowlists, separate privileged writes from user-controlled writes, and add negative tests for protected fields."
  },
  {
    id: "IDOR_DIRECT_OBJECT_ACCESS",
    title: "Direct object access may miss ownership or tenant checks",
    severity: "critical",
    confidence: "low",
    lens: "authorization-boundary",
    match:
      /(findUnique|findById|findOne|getObject|select\s+\*)\s*\([^;\n]*(req\.params|params\.id|query\.id|body\.id|request\.params)/i,
    rootCause:
      "A user-controlled object identifier appears to be used without an adjacent ownership, tenant, or role constraint.",
    safeReproduction:
      "Create two synthetic local/UAT users and confirm whether one user's object can be retrieved by the other using only owned test data.",
    counterfactual:
      "Without this bug, object IDs alone should not grant access. With it, users may cross account, organization, or tenant boundaries.",
    remediation:
      "Bind object lookup to the authenticated principal, tenant, and authorization policy, then test cross-user negative cases."
  },
  {
    id: "CORS_CREDENTIALS_WILDCARD",
    title: "CORS configuration may expose credentialed responses",
    severity: "high",
    confidence: "medium",
    lens: "confidentiality",
    match:
      /(Access-Control-Allow-Origin["']?\s*,\s*["']\*|origin\s*:\s*["']\*["'][^;\n]*credentials\s*:\s*true|credentials\s*:\s*true[^;\n]*origin\s*:\s*["']\*["'])/i,
    rootCause:
      "Credentialed cross-origin responses appear to be allowed too broadly.",
    safeReproduction:
      "Use a local browser fixture or UAT owned account to inspect response headers without accessing third-party data.",
    counterfactual:
      "Without this bug, only trusted origins can read credentialed responses. With it, hostile origins may read sensitive responses in a user's browser context.",
    remediation:
      "Use an explicit origin allowlist, avoid wildcard origins for credentialed routes, and test sensitive endpoints for strict CORS headers."
  },
  {
    id: "UNSAFE_DESERIALIZATION",
    title: "Untrusted data may reach unsafe deserialization",
    severity: "critical",
    confidence: "medium",
    lens: "trusted-execution",
    match:
      /(pickle\.loads|yaml\.load\s*\(|ObjectInputStream|BinaryFormatter|unserialize\s*\(|Marshal\.load|eval\s*\([^;\n]*(req\.|request\.|params|query|body|input))/i,
    rootCause:
      "Untrusted input appears to reach a deserializer or evaluator capable of constructing executable or privileged objects.",
    safeReproduction:
      "Use a local harness with benign synthetic payloads that demonstrate parser selection or object construction behavior without executing harmful code.",
    counterfactual:
      "Without this bug, untrusted data is parsed as inert data. With it, an actor may influence trusted execution or application state.",
    remediation:
      "Use safe parsers, disable arbitrary object construction, avoid eval-like behavior, and validate schemas before parsing."
  },
  {
    id: "XXE_XML_PARSER",
    title: "XML parser may allow external entity resolution",
    severity: "high",
    confidence: "medium",
    lens: "confidentiality",
    match:
      /(DocumentBuilderFactory|SAXParserFactory|xml2js|lxml|etree|XmlReader)[^;\n]*(external|entity|DTD|resolve)/i,
    rootCause:
      "XML parsing appears to support external entity, DTD, or resolver behavior near untrusted input.",
    safeReproduction:
      "Use a local parser fixture with synthetic XML and an owned local file or mock resolver to prove configuration behavior.",
    counterfactual:
      "Without this bug, XML input cannot read local resources or trigger network fetches. With it, parsing may cross file or network trust boundaries.",
    remediation:
      "Disable DTDs, external entities, and external schemas; use hardened parser defaults; and regression-test parser configuration."
  },
  {
    id: "EVM_TX_ORIGIN_AUTH",
    title: "Smart contract authorization may rely on tx.origin",
    severity: "critical",
    confidence: "high",
    lens: "asset-custody",
    match: /tx\.origin/i,
    rootCause:
      "Contract authorization appears to rely on `tx.origin`, which can confuse the initiating wallet with the immediate caller.",
    safeReproduction:
      "Use a local Foundry/Anvil fork test with synthetic accounts to prove whether an intermediate contract can satisfy the authorization condition.",
    counterfactual:
      "Without this bug, only the intended caller can authorize sensitive actions. With it, phishing or proxy flows may cross asset-custody boundaries.",
    remediation:
      "Use `msg.sender` with explicit role checks and add tests for calls through intermediate contracts."
  },
  {
    id: "EVM_UNPROTECTED_DELEGATECALL",
    title: "Delegatecall may be reachable without strict target control",
    severity: "critical",
    confidence: "medium",
    lens: "trusted-execution",
    match: /(delegatecall\s*\(|selfdestruct\s*\(|suicide\s*\()/i,
    rootCause:
      "Powerful EVM primitives appear in code and may affect storage, control flow, or contract lifetime if reachable by untrusted actors.",
    safeReproduction:
      "Use local fork tests only. Prove reachability and authorization boundaries with synthetic contracts and accounts.",
    counterfactual:
      "Without this bug, untrusted callers cannot alter trusted execution or destroy custody logic. With it, they may affect contract control or assets.",
    remediation:
      "Restrict privileged primitives to audited upgrade paths, validate targets, and add access-control and invariant tests."
  },
  {
    id: "GITHUB_ACTIONS_PRIVILEGED_PULL_REQUEST",
    title: "CI workflow may expose privileged token behavior to pull requests",
    severity: "critical",
    confidence: "medium",
    lens: "trusted-execution",
    match:
      /(pull_request_target|permissions\s*:\s*write-all|GITHUB_TOKEN[^;\n]*(write|admin)|secrets\.[A-Z0-9_]+[^;\n]*(pull_request|checkout))/i,
    rootCause:
      "CI configuration appears to combine untrusted pull-request code with privileged tokens, secrets, or write permissions.",
    safeReproduction:
      "Do not open a malicious PR. Locally inspect workflow triggers, permissions, and checkout behavior to prove whether untrusted code can run with privileges.",
    counterfactual:
      "Without this bug, untrusted contributions cannot access release credentials or repository write tokens. With it, trusted execution or supply-chain integrity may be affected.",
    remediation:
      "Separate untrusted PR validation from privileged workflows, pin permissions to least privilege, and avoid checking out attacker-controlled code in privileged contexts."
  },
  {
    id: "CLOUD_PUBLIC_ACCESS_OR_WILDCARD_IAM",
    title: "Cloud policy may allow public or wildcard privileged access",
    severity: "critical",
    confidence: "medium",
    lens: "confidentiality",
    match:
      /("Principal"\s*:\s*"\*"|"Action"\s*:\s*"\*"|"Resource"\s*:\s*"\*"|allUsers|allAuthenticatedUsers|public-read|0\.0\.0\.0\/0[^;\n]*(admin|ssh|rdp|database|redis))/i,
    rootCause:
      "Infrastructure policy appears to grant broad public or wildcard access near sensitive resources or permissions.",
    safeReproduction:
      "Do not access cloud resources. Review the in-scope configuration locally and, if needed, ask the program for confirmation through the report.",
    counterfactual:
      "Without this bug, only intended identities or networks can access the resource. With it, broad actors may read data or perform privileged actions.",
    remediation:
      "Replace wildcard principals/actions/resources with least-privilege policies, restrict networks, and add policy-as-code checks."
  }
];

export function analyzeCode(input: AnalyzeCodeInput): AnalysisResult {
  const lines = input.code.split(/\r?\n/);
  const targetClass = classifySource(input.fileName, input.code);
  const guardChecks: GuardCheck[] = [
    evaluateAction(input.policy, "local static source review", input.policy.allowlist[0] ?? "local")
  ];
  const findings = rules.flatMap((rule) =>
    collectMatches(rule, lines, input.fileName)
  );
  const surfaces = deriveSurfaces(targetClass, findings, input.policy.allowlist[0]);
  const hypotheses = findings.map((finding, index) =>
    findingToHypothesis(finding, index + 1)
  );

  return {
    targetClass,
    findings,
    hypotheses,
    surfaces,
    guardChecks,
    summary: {
      scannedLines: lines.length,
      criticalCandidates: findings.filter((finding) => finding.severity === "critical").length,
      highCandidates: findings.filter((finding) => finding.severity === "high").length,
      safeMode: guardChecks.every((check) => check.decision === "allow")
    }
  };
}

function collectMatches(rule: Rule, lines: string[], fileName: string): CodeFinding[] {
  const findings: CodeFinding[] = [];

  lines.forEach((line, index) => {
    if (!rule.match.test(line)) {
      return;
    }

    findings.push({
      id: `${rule.id}-${hashId(fileName)}-${index + 1}`,
      title: rule.title,
      severity: rule.severity,
      confidence: rule.confidence,
      lens: rule.lens,
      fileName,
      line: index + 1,
      snippet: redactSensitive(line.trim()),
      rootCause: rule.rootCause,
      safeReproduction: rule.safeReproduction,
      counterfactual: rule.counterfactual,
      remediation: rule.remediation,
      evidenceStandard: [
        "Use only local, fork, UAT, or owned-account evidence.",
        "Show the minimal behavior delta needed for triage.",
        "Redact secrets and avoid third-party data."
      ],
      guardrails: [
        "No destructive validation.",
        "No production writes.",
        "Stop if unexpected third-party data appears."
      ]
    });
  });

  return findings;
}

function classifySource(fileName: string, code: string): TargetClass {
  if (/\.(sol)$/i.test(fileName) || /contract\s+\w+/i.test(code)) {
    return "EVM_CONTRACT";
  }

  if (/android|apk|intent|activity/i.test(fileName + code)) {
    return "MOBILE_APP";
  }

  if (/workflow|github-actions|package\.json|setup\.py|release/i.test(fileName)) {
    return "SUPPLY_CHAIN";
  }

  if (/express|fastify|next\/server|route|controller|request|response|req\./i.test(code)) {
    return "WEB_API";
  }

  return "SOURCE_REPO";
}

function deriveSurfaces(
  targetClass: TargetClass,
  findings: CodeFinding[],
  fallbackAsset?: string
): ImpactSurface[] {
  const surfacesByLens = new Map<CriticalLens, CodeFinding[]>();

  findings.forEach((finding) => {
    const list = surfacesByLens.get(finding.lens) ?? [];
    list.push(finding);
    surfacesByLens.set(finding.lens, list);
  });

  if (surfacesByLens.size === 0) {
    return [
      {
        id: "SURF-BASELINE",
        title: "No critical pattern matched yet",
        lens: "business-logic",
        targetAsset: fallbackAsset ?? "local source snapshot",
        trustBoundary: "To be derived from routes, roles, and protected objects.",
        safeValidationEnvironment: "local",
        criticalityRationale:
          "Continue mapping high-value trust boundaries before attempting validation.",
        priority: 5
      }
    ];
  }

  return [...surfacesByLens.entries()].map(([lens, lensFindings], index) => ({
    id: `SURF-${String(index + 1).padStart(3, "0")}`,
    title: `${labelForLens(lens)} surface in ${targetClass}`,
    lens,
    targetAsset: fallbackAsset ?? "local source snapshot",
    trustBoundary: lensFindings[0]?.counterfactual ?? "Derived from matched code path.",
    safeValidationEnvironment: "local / fork / UAT only",
    criticalityRationale: `${lensFindings.length} candidate signal(s) map to ${labelForLens(lens).toLowerCase()} impact.`,
    priority: lensFindings.some((finding) => finding.severity === "critical") ? 1 : 2
  }));
}

function findingToHypothesis(finding: CodeFinding, ordinal: number): Hypothesis {
  return {
    id: `HYP-${String(ordinal).padStart(4, "0")}`,
    claim: `${finding.title} at ${finding.fileName}:${finding.line} may produce ${finding.severity} impact if the trust boundary is reachable.`,
    lens: finding.lens,
    targetAssets: [finding.fileName],
    assumptions: [
      "The matched code path is reachable by an untrusted or lower-privileged actor.",
      "No upstream authorization, validation, or compensating control fully removes the impact."
    ],
    safeValidationPlan: {
      environment: "local, fork, UAT, or owned-account test only",
      maxContact: "No production writes and no destructive actions",
      dataHandling: "Synthetic, owned, redacted, or aggregate evidence only"
    },
    stopConditions: [
      "Out-of-scope asset encountered",
      "Unexpected third-party data appears",
      "Validation requires destructive behavior"
    ],
    evidenceRequired: finding.evidenceStandard,
    status: "OPEN"
  };
}

function labelForLens(lens: CriticalLens): string {
  return lens
    .split("-")
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

function redactSensitive(snippet: string): string {
  return snippet.replace(
    /(["'])([A-Za-z0-9_./+=-]{8})([A-Za-z0-9_./+=-]{8,})(["'])/g,
    "$1$2...[redacted]$4"
  );
}

function hashId(value: string): string {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return hash.toString(36);
}
