"""Generic subclass detection for the harness scaffolder.

Pure, offline token-scoring that routes a web/crypto target to the right *generic* harness
skeleton (e.g. payments vs auth vs graphql; signature vs cipher vs kdf vs zk). This is CLASS-level
routing — which kind of property test to start from — never a per-target playbook or a list of
bugs. Extracted from the retired ``knowledge_packs`` bug-catalog so the scaffolder keeps its
class routing without dragging in preset vulnerability knowledge.
"""

from __future__ import annotations

from pathlib import Path

_WEB_EXTS = {".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".php", ".java", ".cs"}
_CRYPTO_EXTS = {".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".go", ".py"}
_IGNORE_DIRS = {"node_modules", ".git", ".next", "dist", "build", "vendor", "target", ".venv", ".p1hunt-poc"}
_MAX_FILES = 600

# Web-API subclass routing lexicon (which generic harness template to start from).
_WEB_SUBCLASS_TOKENS: dict[str, tuple[str, ...]] = {
    "payments": (
        "payment", "charge", "checkout", "invoice", "refund", "discount", "coupon",
        "currency", "stripe", "paypal", "webhook", "idempotency", "idempotency-key",
        "idempotency_key", "ledger", "transaction", "subscription", "price", "amount",
        "balance", "wallet", "payout",
    ),
    "auth": (
        "login", "logout", "signup", "register", "password", "reset", "forgot",
        "otp", "mfa", "2fa", "totp", "oauth", "oidc", "pkce", "redirect_uri",
        "jwt", "bearer", "token", "session", "account-takeover", "verify-email",
        "verifyemail", "magic-link", "magiclink", "credential",
    ),
    "graphql": (
        "graphql", "apollo", "resolver", "resolvers", "typedefs", "type_defs",
        "schema.graphql", "introspection", "__schema", "__type", "query {",
        "mutation {", "subscription {", "datasource", "gql`", "buildschema",
        "graphql-yoga", "graphql_yoga",
    ),
    "rest": (
        "router", "route", "controller", "endpoint", "@get", "@post", "@put",
        "@delete", "@patch", "app.get", "app.post", "app.put", "app.delete",
        "req.params", "req.query", "req.body", "request.args", "pathparam",
        "@requestmapping", "@getmapping", "@postmapping", "openapi", "swagger",
        "/api/", "restful",
    ),
}
_WEB_SUBCLASS_PRIORITY: tuple[str, ...] = ("payments", "auth", "graphql", "rest")

# Crypto-lib subclass routing lexicon.
_CRYPTO_SUBCLASS_TOKENS: dict[str, tuple[str, ...]] = {
    "zk": (
        "zk", "zksnark", "snark", "stark", "plonk", "groth16", "proof", "prover",
        "verifier", "circuit", "witness", "fiat-shamir", "fiat_shamir", "transcript",
        "nullifier", "commitment", "trusted setup", "toxic waste", "r1cs", "constraint",
        "merkle", "public input", "publicinput", "soundness",
    ),
    "signature": (
        "ecdsa", "eddsa", "ed25519", "secp256k1", "schnorr", "sign", "signature",
        "verify", "recover", "nonce", "malleab", "low-s", "low_s", "rfc6979",
        "der", "r,s", "pubkey", "publickey", "privatekey", "batch verify",
        "batchverify",
    ),
    "kdf": (
        "kdf", "hkdf", "pbkdf2", "pbkdf", "scrypt", "argon2", "bcrypt", "salt",
        "derive", "derivekey", "derive_key", "iteration", "cost", "info", "ikm",
        "okm", "stretch", "password hash", "passwordhash",
    ),
    "cipher": (
        "aes", "aes-gcm", "aes_gcm", "gcm", "chacha", "chacha20", "poly1305",
        "aead", "encrypt", "decrypt", "cipher", "ctr", "cbc", "padding", "iv",
        "nonce", "block cipher", "blockcipher", "stream cipher", "tag", "seal",
        "open",
    ),
}
_CRYPTO_SUBCLASS_PRIORITY: tuple[str, ...] = ("zk", "signature", "kdf", "cipher")


def _iter_source_text(repo_path: str, exts: set[str]) -> list[tuple[str, str]]:
    """Return (lowercased-relative-name, lowercased-content) for in-scope source files.
    Scans up to ``_MAX_FILES`` files whose extension is in ``exts``, skipping ``_IGNORE_DIRS``.
    Pure and offline; never raises (best-effort, swallows IO errors)."""
    root = Path(repo_path)
    out: list[tuple[str, str]] = []
    if not root.exists():
        return out
    scanned = 0
    for path in sorted(root.rglob("*")):
        if scanned >= _MAX_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = path
        if any(part in _IGNORE_DIRS for part in rel.parts):
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        out.append((str(rel).lower(), text.lower()))
    return out


def _score_subclasses(
    files: list[tuple[str, str]], lexicon: dict[str, tuple[str, ...]]
) -> dict[str, int]:
    """Weighted token scoring over file names + contents (name tokens count double)."""
    scores: dict[str, int] = {name: 0 for name in lexicon}
    for name, content in files:
        for sub, tokens in lexicon.items():
            for tok in tokens:
                if tok in name:
                    scores[sub] += 2
                if tok in content:
                    scores[sub] += content.count(tok)
    return scores


def detect_web_subclass(repo_path: str, signal_ids: list[str] | None = None) -> str:
    """Route a web-API target to a generic harness subclass (PURE). Returns ``"generic-web"``
    when there is no source or no class signal stands out."""
    files = _iter_source_text(repo_path, _WEB_EXTS)
    if not files:
        return "generic-web"
    scores = _score_subclasses(files, _WEB_SUBCLASS_TOKENS)
    sig = {s.lower() for s in (signal_ids or [])}
    if any("auth" in s or "jwt" in s or "oauth" in s or "session" in s for s in sig):
        scores["auth"] += 1
    if any("payment" in s or "idor" in s or "bola" in s for s in sig):
        scores["payments" if any("payment" in s for s in sig) else "rest"] += 1
    best_score = max(scores.values())
    if best_score == 0:
        return "generic-web"
    top = {sub for sub, sc in scores.items() if sc == best_score}
    for sub in _WEB_SUBCLASS_PRIORITY:
        if sub in top:
            return sub
    return "generic-web"


def detect_crypto_subclass(repo_path: str, signal_ids: list[str] | None = None) -> str:
    """Route a crypto-lib target to a generic harness subclass (PURE). Returns
    ``"generic-crypto"`` when there is no source or no class signal stands out."""
    files = _iter_source_text(repo_path, _CRYPTO_EXTS)
    if not files:
        return "generic-crypto"
    scores = _score_subclasses(files, _CRYPTO_SUBCLASS_TOKENS)
    sig = {s.lower() for s in (signal_ids or [])}
    if any("nonce" in s or "malleab" in s or "ecdsa" in s for s in sig):
        scores["signature"] += 1
    if any("zk" in s or "proof" in s or "snark" in s for s in sig):
        scores["zk"] += 1
    best_score = max(scores.values())
    if best_score == 0:
        return "generic-crypto"
    top = {sub for sub, sc in scores.items() if sc == best_score}
    for sub in _CRYPTO_SUBCLASS_PRIORITY:
        if sub in top:
            return sub
    return "generic-crypto"
