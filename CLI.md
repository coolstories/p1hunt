# P1Scan Terminal App

P1Scan is a terminal-first safe-harbor scanner for finding P1 vulnerability
candidates in authorized local codebases.

It does not exploit live systems. It performs local repository search, ranks
critical-impact candidates, optionally asks Claude Agent SDK to triage in plan mode,
and exports a human-review report.

## Run

```sh
npm run p1scan
```

## Enterprise Setup

```sh
npm run p1scan -- init
npm run p1scan -- status
npm run p1scan -- config set organization "Acme Security"
npm run p1scan -- config set policyProfile enterprise-audit
```

P1Scan stores enterprise runtime files under `.p1scan/`:

- `.p1scan/config.json`
- `.p1scan/audit/*.jsonl`
- `.p1scan/reports/*`

## Commands

```sh
init
status
config show
config set <key> <value>
scan ./target --agent --max-files 800
hunt ./target --rounds 4 --agent --json p1scan-run.json
hunt ./target --rounds 4 --agent --report p1scan-report.md --json p1scan-run.json
findings
agent
audit
report p1scan-report.md
scope
quit
```

## One-Shot Usage

```sh
npm run p1scan:scan -- ./data/fixtures --max-files 100 --json p1scan-run.json
npm run p1scan:hunt -- ./data/fixtures --rounds 3 --agent --report p1scan-report.md
```

## Claude Agent SDK

Set `ANTHROPIC_API_KEY` to enable Claude triage:

```sh
export ANTHROPIC_API_KEY=...
npm run p1scan:hunt -- ./target --agent
```

Claude runs with:

- `permissionMode: "plan"`
- no tools
- deny-all permission callback
- redacted local finding summaries only

## Enterprise Artifacts

Every terminal run can produce:

- Markdown report via `--report`
- Full JSON run artifact via `--json`
- Append-only audit log events under `.p1scan/audit/`
- Account metadata when Claude Agent SDK auth is available

## Output

P1Scan reports candidates, not guaranteed vulnerabilities. A candidate becomes a real
finding only after safe reproduction in local, fork, UAT, testnet, or owned-account
environments and human review.
