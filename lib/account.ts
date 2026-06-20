import type { AccountStatus } from "./types";

export async function getAccountStatus(): Promise<AccountStatus> {
  const envStatus = detectEnvironmentAccount();
  if (!envStatus.connected) {
    return envStatus;
  }

  const sdkStatus = await lookupSdkAccountInfo();
  return sdkStatus ?? envStatus;
}

function detectEnvironmentAccount(): AccountStatus {
  if (process.env.ANTHROPIC_API_KEY) {
    return {
      connected: true,
      provider: "anthropic",
      source: "api-key",
      detail: "ANTHROPIC_API_KEY is configured for Claude Agent SDK triage."
    };
  }

  if (process.env.CLAUDE_CODE_USE_BEDROCK) {
    return {
      connected: true,
      provider: "bedrock",
      source: "cloud",
      detail: "Claude Agent SDK is configured to use Bedrock."
    };
  }

  if (process.env.CLAUDE_CODE_USE_VERTEX) {
    return {
      connected: true,
      provider: "vertex",
      source: "cloud",
      detail: "Claude Agent SDK is configured to use Vertex."
    };
  }

  if (process.env.CLAUDE_CODE_USE_GATEWAY) {
    return {
      connected: true,
      provider: "gateway",
      source: "environment",
      detail: "Claude Agent SDK gateway mode is configured."
    };
  }

  return {
    connected: false,
    provider: "unknown",
    source: "none",
    detail:
      "No Claude Agent SDK credentials detected. Set ANTHROPIC_API_KEY or configure Bedrock/Vertex/gateway auth."
  };
}

async function lookupSdkAccountInfo(): Promise<AccountStatus | null> {
  try {
    const { query } = await import("@anthropic-ai/claude-agent-sdk");
    const accountPromise = (async () => {
      const session = query({
        prompt: "Return the word READY. Do not use tools.",
        options: {
          maxTurns: 1,
          permissionMode: "plan",
          tools: [],
          canUseTool: async () => ({
            behavior: "deny",
            message: "P1Scan account status does not permit tool use."
          })
        }
      });
      const account = await session.accountInfo();
      await session.interrupt().catch(() => undefined);
      return account;
    })();

    const account = await withTimeout(accountPromise, 4_000);
    return {
      connected: true,
      provider: providerFromSdk(account.apiProvider),
      source: account.apiKeySource === "oauth" ? "oauth" : "api-key",
      email: account.email,
      organization: account.organization,
      subscriptionType: account.subscriptionType,
      detail: "Claude Agent SDK account lookup succeeded."
    };
  } catch {
    return null;
  }
}

function providerFromSdk(provider: string | undefined): AccountStatus["provider"] {
  if (provider === "bedrock") {
    return "bedrock";
  }
  if (provider === "vertex") {
    return "vertex";
  }
  if (provider === "gateway") {
    return "gateway";
  }
  if (provider === "firstParty") {
    return "anthropic";
  }
  return "unknown";
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => reject(new Error("timeout")), timeoutMs);
  });

  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}
