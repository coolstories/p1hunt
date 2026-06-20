"""Sample scopes + a synthetic vulnerable target (for demos and acceptance tests).

The vulnerable fixture is fully synthetic and owned — it exists only so the swarm has a
local artifact to hunt safely. The three sample scopes (web/api, EVM, crypto-lib) drive the
no-presets divergence test (§16): each must yield a materially different EngagementPlan.
"""

from __future__ import annotations

from pathlib import Path

from .models import Asset, Scope

_TAXONOMY = {
    "P1": "Critical: authorization bypass across tenants, asset-custody loss, trusted-execution compromise, or sensitive data exposure at scale.",
    "P2": "High: a protected workflow or privileged operation with meaningful prerequisites.",
    "P3": "Medium: limited data or narrow reachability.",
    "P4": "Low / informational.",
}


def sample_web_scope() -> Scope:
    return Scope(
        program="Example Safe Harbor Program",
        platform="Bug bounty platform",
        disclosure_channel="security@example.org",
        safe_harbor_text=(
            "Testing is authorized only against listed assets, owned accounts, local forks, "
            "and UAT environments. Destructive testing and third-party data access are prohibited."
        ),
        severity_taxonomy=dict(_TAXONOMY),
        in_scope=[
            Asset("a1", "Local source snapshot", "repo", "local-source", "local"),
            Asset("a2", "UAT API tenant", "domain", "uat.example.org", "uat"),
        ],
        out_of_scope=[Asset("a3", "Production API", "domain", "api.example.org", "production")],
        rules=[
            "Use only owned accounts or synthetic data.",
            "No production writes.",
            "No denial-of-service testing.",
            "Reports must include safe reproduction steps and remediation guidance.",
        ],
        rate_limit="30 requests per minute maximum for approved live checks",
        source_urls=["https://example.org/security"],
    )


def sample_evm_scope() -> Scope:
    return Scope(
        program="Example DeFi Protocol",
        platform="Immunefi",
        disclosure_channel="https://immunefi.com/bounty/example",
        safe_harbor_text="Fork and testnet testing only. No mainnet transactions. PoC must be a fork test.",
        severity_taxonomy=dict(_TAXONOMY),
        in_scope=[Asset("c1", "Vault contract", "contract", "local-contracts", "local")],
        out_of_scope=[Asset("c2", "Mainnet deployment", "contract", "0xMAINNET", "production")],
        rules=["Fork-only.", "No mainnet writes.", "PoC via Foundry invariant test."],
        rate_limit="n/a",
    )


def sample_crypto_scope() -> Scope:
    return Scope(
        program="Example Crypto Library",
        platform="HackerOne",
        disclosure_channel="security@cryptolib.example",
        safe_harbor_text="Local harness only. No network. Memory-safety and protocol findings welcome.",
        severity_taxonomy=dict(_TAXONOMY),
        in_scope=[Asset("l1", "libexample source", "repo", "local-cryptolib", "local")],
        out_of_scope=[],
        rules=["Local harness only.", "No network."],
        rate_limit="n/a",
    )


_VULN_WEB = '''\
import express from "express";
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

app.get("/user/:id", async (req, res) => {
  const user = await db.findUnique(req.params.id);
  res.json(user);
});

const apiKey = "sk_live_exampleSecretValue123456789";
'''

_VULN_SOL = '''\
pragma solidity ^0.8.0;

contract Vault {
    mapping(address => uint256) public balances;
    address public owner;

    // invariant: total balances must equal contract balance
    function withdraw(uint256 amount) external {
        require(tx.origin == owner, "not owner"); // tx.origin auth
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount;
    }

    function upgrade(address impl, bytes calldata data) external {
        impl.delegatecall(data); // unprotected delegatecall
    }
}
'''


def write_vulnerable_target(root: str | Path, kind: str = "web") -> str:
    """Write a synthetic, owned vulnerable target for safe hunting. Returns the path."""
    base = Path(root)
    base.mkdir(parents=True, exist_ok=True)
    if kind == "evm":
        (base / "Vault.sol").write_text(_VULN_SOL, encoding="utf-8")
    else:
        (base / "routes.ts").write_text(_VULN_WEB, encoding="utf-8")
    return str(base)
