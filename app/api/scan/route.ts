import { NextResponse } from "next/server";
import { getDefaultScanOptions, scanRepository } from "@/lib/repository-scanner";
import { deriveScopeGuardPolicy } from "@/lib/scopeguard";
import { sampleScope } from "@/lib/sample-engagement";
import type { ScanOptions, Scope, ScopeGuardPolicy } from "@/lib/types";

interface ScanRequest {
  rootPath?: string;
  options?: Partial<ScanOptions>;
  scope?: Scope;
  policy?: ScopeGuardPolicy;
}

export async function POST(request: Request) {
  const body = (await request.json()) as ScanRequest;
  const scope = body.scope ?? sampleScope;
  const policy = body.policy ?? deriveScopeGuardPolicy(scope);
  const defaults = getDefaultScanOptions(body.rootPath || process.cwd());
  const options: ScanOptions = {
    ...defaults,
    ...body.options,
    rootPath: body.rootPath || body.options?.rootPath || defaults.rootPath,
    includeExtensions:
      body.options?.includeExtensions?.length ? body.options.includeExtensions : defaults.includeExtensions,
    ignoreDirectories:
      body.options?.ignoreDirectories?.length ? body.options.ignoreDirectories : defaults.ignoreDirectories,
    maxFiles: Math.min(body.options?.maxFiles ?? defaults.maxFiles, 1_500),
    maxBytesPerFile: Math.min(
      body.options?.maxBytesPerFile ?? defaults.maxBytesPerFile,
      1_000_000
    )
  };

  try {
    const result = await scanRepository(options, policy, scope);
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : "Repository scan failed."
      },
      { status: 400 }
    );
  }
}
