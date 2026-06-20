import { NextResponse } from "next/server";
import { analyzeCode } from "@/lib/analyzer";
import { runClaudeTriage } from "@/lib/claude-agent";
import { deriveScopeGuardPolicy } from "@/lib/scopeguard";
import { sampleScope } from "@/lib/sample-engagement";
import type { Scope, ScopeGuardPolicy } from "@/lib/types";

interface AnalyzeRequest {
  code?: string;
  fileName?: string;
  scope?: Scope;
  policy?: ScopeGuardPolicy;
  enableClaudeTriage?: boolean;
}

export async function POST(request: Request) {
  const body = (await request.json()) as AnalyzeRequest;
  const code = body.code?.trim();

  if (!code) {
    return NextResponse.json(
      { error: "Code is required for local analysis." },
      { status: 400 }
    );
  }

  const scope = body.scope ?? sampleScope;
  const policy = body.policy ?? deriveScopeGuardPolicy(scope);
  const result = analyzeCode({
    code,
    fileName: body.fileName?.trim() || "source.ts",
    policy
  });
  result.agentTriage = await runClaudeTriage({
    enabled: body.enableClaudeTriage ?? false,
    findings: result.findings.slice(0, 25),
    scope,
    rootPath: process.cwd()
  });

  return NextResponse.json(result);
}
