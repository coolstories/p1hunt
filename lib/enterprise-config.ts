import { mkdir, readFile, writeFile } from "fs/promises";
import path from "path";
import type { EnterpriseConfig, PolicyProfile } from "./types";

const configFileName = "config.json";

export function enterpriseHome(rootPath = process.cwd()) {
  return path.join(rootPath, ".p1scan");
}

export function configPath(rootPath = process.cwd()) {
  return path.join(enterpriseHome(rootPath), configFileName);
}

export function defaultEnterpriseConfig(rootPath = process.cwd()): EnterpriseConfig {
  const home = enterpriseHome(rootPath);
  return {
    version: 1,
    organization: process.env.P1SCAN_ORG ?? "Local Security Team",
    policyProfile: policyFromEnv(process.env.P1SCAN_POLICY),
    defaultRootPath: rootPath,
    maxFiles: Number(process.env.P1SCAN_MAX_FILES ?? 750),
    maxBytesPerFile: Number(process.env.P1SCAN_MAX_BYTES_PER_FILE ?? 500_000),
    enableClaudeTriage: process.env.P1SCAN_AGENT === "1",
    requireHumanReview: true,
    auditDirectory: path.join(home, "audit"),
    reportDirectory: path.join(home, "reports")
  };
}

export async function loadEnterpriseConfig(rootPath = process.cwd()): Promise<EnterpriseConfig> {
  try {
    const raw = await readFile(configPath(rootPath), "utf8");
    return normalizeConfig(JSON.parse(raw) as Partial<EnterpriseConfig>, rootPath);
  } catch {
    return defaultEnterpriseConfig(rootPath);
  }
}

export async function writeEnterpriseConfig(
  config: EnterpriseConfig,
  rootPath = process.cwd()
): Promise<void> {
  await mkdir(enterpriseHome(rootPath), { recursive: true });
  await mkdir(config.auditDirectory, { recursive: true });
  await mkdir(config.reportDirectory, { recursive: true });
  await writeFile(configPath(rootPath), `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

export async function initializeEnterpriseConfig(rootPath = process.cwd()) {
  const config = defaultEnterpriseConfig(rootPath);
  await writeEnterpriseConfig(config, rootPath);
  return config;
}

function normalizeConfig(input: Partial<EnterpriseConfig>, rootPath: string): EnterpriseConfig {
  const defaults = defaultEnterpriseConfig(rootPath);
  return {
    ...defaults,
    ...input,
    version: 1,
    policyProfile: policyFromEnv(input.policyProfile ?? defaults.policyProfile),
    maxFiles: clampNumber(input.maxFiles, defaults.maxFiles, 1, 10_000),
    maxBytesPerFile: clampNumber(input.maxBytesPerFile, defaults.maxBytesPerFile, 1_000, 5_000_000),
    requireHumanReview: input.requireHumanReview ?? true
  };
}

function policyFromEnv(value: string | undefined): PolicyProfile {
  if (value === "enterprise-audit" || value === "offline-only" || value === "bug-bounty-safe") {
    return value;
  }
  return "enterprise-audit";
}

function clampNumber(value: number | undefined, fallback: number, min: number, max: number) {
  if (!Number.isFinite(value)) {
    return fallback;
  }
  return Math.min(Math.max(Number(value), min), max);
}
