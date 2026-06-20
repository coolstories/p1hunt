import type { Engagement, Scope } from "./types";
import { deriveScopeGuardPolicy, getDefaultPhases } from "./scopeguard";

export const sampleScope: Scope = {
  program: "Example Safe Harbor Program",
  platform: "Bug bounty platform",
  disclosureChannel: "security@example.org",
  safeHarborText:
    "Testing is authorized only against listed assets, owned accounts, local forks, and UAT environments. Destructive testing and third-party data access are prohibited.",
  severityTaxonomy: {
    P1: "Critical impact such as authorization bypass across tenants, asset custody loss, trusted execution compromise, or sensitive data exposure at scale.",
    P2: "High impact affecting a protected workflow, sensitive object, or privileged operation with meaningful prerequisites.",
    P3: "Medium impact with limited data, narrow reachability, or substantial user interaction.",
    P4: "Low impact, hardening issue, or informational weakness."
  },
  inScope: [
    {
      id: "asset-1",
      label: "Local source snapshot",
      type: "repo",
      value: "local-source",
      environment: "local"
    },
    {
      id: "asset-2",
      label: "UAT API tenant",
      type: "domain",
      value: "uat.example.org",
      environment: "uat"
    }
  ],
  outOfScope: [
    {
      id: "asset-3",
      label: "Production API",
      type: "domain",
      value: "api.example.org",
      environment: "production"
    }
  ],
  ambiguous: [],
  rules: [
    "Use only owned accounts or synthetic data.",
    "No production writes.",
    "No denial-of-service testing.",
    "No social engineering.",
    "Reports must include safe reproduction steps and remediation guidance."
  ],
  rateLimit: "30 requests per minute maximum for approved live checks"
};

export const sampleCode = `import express from "express";
import { exec } from "child_process";
import db from "./db";

const app = express();

app.get("/admin/export", async (req, res) => {
  if (req.query.debug === "1") return true; // TODO temporary admin bypass
  const rows = await db.query("SELECT * FROM users WHERE org_id = " + req.query.orgId);
  res.json(rows);
});

app.get("/avatar", async (req, res) => {
  const image = await fetch(req.query.url as string);
  res.send(await image.text());
});

app.post("/convert", (req, res) => {
  exec("convert " + req.body.fileName, () => res.send("ok"));
});

const apiKey = "sk_live_exampleSecretValue123456789";
`;

export function createSampleEngagement(): Engagement {
  const policy = deriveScopeGuardPolicy(sampleScope);

  return {
    id: "eng-example",
    status: "READY",
    scope: sampleScope,
    policy,
    phases: getDefaultPhases(),
    surfaces: [],
    hypotheses: [],
    findings: []
  };
}
