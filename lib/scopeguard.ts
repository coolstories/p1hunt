import type { Asset, GuardCheck, Scope, ScopeGuardPolicy, WorkflowPhase } from "./types";

const destructiveTerms = [
  "delete",
  "drop",
  "truncate",
  "destroy",
  "shutdown",
  "spam",
  "flood",
  "bruteforce",
  "credential-stuff",
  "mainnet-write",
  "prod-write",
  "disable",
  "lockout"
];

export function deriveScopeGuardPolicy(scope: Scope): ScopeGuardPolicy {
  const allowedHttpMethods = scope.rules.some((rule) =>
    /post|put|patch|delete/i.test(rule)
  )
    ? ["GET", "HEAD", "OPTIONS"]
    : ["GET", "HEAD"];

  return {
    allowlist: scope.inScope.map((asset) => asset.value),
    denylist: [...scope.outOfScope.map((asset) => asset.value), ...destructiveTerms],
    sandboxEnvironments: ["local", "fork", "testnet", "uat"],
    allowedHttpMethods,
    maxRequestsPerMinute: parseRateLimit(scope.rateLimit),
    unattendedMode: true,
    evidenceMode: "least-data"
  };
}

export function evaluateAction(
  policy: ScopeGuardPolicy,
  action: string,
  target: string,
  asset?: Asset
): GuardCheck {
  const normalizedAction = action.toLowerCase();
  const normalizedTarget = target.toLowerCase();
  const inAllowlist = policy.allowlist.some((allowed) =>
    normalizedTarget.includes(allowed.toLowerCase())
  );
  const deniedByTerm = policy.denylist.some((denied) =>
    normalizedAction.includes(denied.toLowerCase()) ||
    normalizedTarget.includes(denied.toLowerCase())
  );
  const safeEnvironment =
    !asset || policy.sandboxEnvironments.includes(asset.environment);

  if (!inAllowlist) {
    return {
      action,
      target,
      decision: "deny",
      reason: "Target is not on the normalized in-scope allowlist."
    };
  }

  if (deniedByTerm) {
    return {
      action,
      target,
      decision: "deny",
      reason: "Action or target matches a destructive or out-of-scope deny rule."
    };
  }

  if (!safeEnvironment && /write|post|put|patch|delete|transfer|send/i.test(action)) {
    return {
      action,
      target,
      decision: "deny",
      reason: "Writes are restricted to local, fork, testnet, or UAT environments."
    };
  }

  return {
    action,
    target,
    decision: "allow",
    reason: "Action is in scope, non-destructive, and compatible with the sandbox policy."
  };
}

export function getDefaultPhases(): WorkflowPhase[] {
  return [
    {
      id: "intake",
      name: "Program Intake",
      requiredOutput: "program.md, scope.json, target_snapshot.json",
      promotionGate: "Human confirms the program is open and asset is in scope.",
      status: "complete"
    },
    {
      id: "safety",
      name: "Safety Policy",
      requiredOutput: "safety_policy.json with allowlist, denylist, sandbox, and rate policy",
      promotionGate: "Guard denies destructive and out-of-scope actions.",
      status: "complete"
    },
    {
      id: "acquisition",
      name: "Target Acquisition",
      requiredOutput: "Immutable target snapshot and local analysis inputs",
      promotionGate: "Only approved assets are fetched or analyzed.",
      status: "active"
    },
    {
      id: "mapping",
      name: "Surface Mapping",
      requiredOutput: "Ranked impact surfaces tied to in-scope assets",
      promotionGate: "Each surface maps to a trust boundary and safe validation environment.",
      status: "pending"
    },
    {
      id: "hypothesis",
      name: "Hypothesis Generation",
      requiredOutput: "Hypotheses with safe validation plans and stop conditions",
      promotionGate: "Every hypothesis has a non-destructive proof strategy.",
      status: "pending"
    },
    {
      id: "testing",
      name: "Safe Testing",
      requiredOutput: "Local/fork/UAT evidence and reproduction notes",
      promotionGate: "No production harm and no third-party data exposure.",
      status: "pending"
    },
    {
      id: "verification",
      name: "Falsification",
      requiredOutput: "Reproduced artifact and adversarial review result",
      promotionGate: "Candidate survives scope, impact, and duplicate review.",
      status: "pending"
    },
    {
      id: "reporting",
      name: "Human-Reviewed Report",
      requiredOutput: "Report package with safe-harbor attestation",
      promotionGate: "Human approves scope, evidence, impact, wording, and channel.",
      status: "pending"
    }
  ];
}

function parseRateLimit(rateLimit: string): number {
  const match = rateLimit.match(/(\d+)/);
  return match ? Number(match[1]) : 30;
}
