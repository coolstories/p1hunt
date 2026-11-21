# Runbook — running a live web hunt

This is the operational path for pointing p1hunt at a web target you are authorized to
test. It is written against what has actually been **measured**, not what the code intends;
where a thing is unverified it says so, because the failure mode of this whole system is a
run that reports success while one layer is dead.

---

## 0. Before anything: `doctor`

```sh
python3 -m p1hunt.main doctor
```

This is the single most useful command here. It answers one question — *would a hunt
started right now mean anything?* — and exits non-zero on **NO-GO** so you can gate a
script on it.

It exists because every expensive failure this project has had was the same shape: **one
dead layer behind a healthy-looking run.** All of these were real, and each cost a run:

| what was dead | what the run looked like |
|---|---|
| the provider refused all five hunters and the fuzzer | ran 315s, reported success, found nothing |
| Playwright couldn't start inside the event loop, so live recon never ran | planner silently got an empty surface |
| a stale pytest plugin killed every harness before collection | confirmed count capped at zero |
| a null token count crashed the final report | exit 1 after a completed hunt; no report |

A clean result from a machine that fails `doctor` tells you **nothing about the target.**

`doctor` reports a check it could not perform as `skip`, never as `ok`. That matters most
for **role acceptance**, which costs a model session per role and so is read from an
artifact rather than guessed:

```sh
python3 bench/probe_refusal.py                  # the configured engine
python3 bench/probe_refusal.py --engine claude
```

---

## 1. Pick an engine that will actually do the work

**This is not a detail. It is the difference between a working hunt and a silent zero.**

A provider-side safety classifier reads each prompt before the model does. When it
refuses, the session returns an error, the role contributes nothing, and the pipeline
*still reports success*. Measured, per role, one short session each:

| role | codex / `gpt-6-astra` | claude / `claude-opus-5-5` |
|---|---|---|
| `web_map` (recon) | ACCEPTED | ACCEPTED |
| `web_hunt` | REFUSED | accepted, then cut off mid-work |
| `materialize`, `repair` | REFUSED | **ACCEPTED** |
| `falsifier` | REFUSED | cut off mid-work |
| `src_hunt`, `fuzz`, `exploit_dev` | REFUSED | mixed |

So on Codex the **entire find-and-prove chain is dead** — only reconnaissance runs. Use:

```sh
export P1HUNT_ENGINE=claude     # needs: pip install 'claude-agent-sdk>=0.2.105'
```

Two honest caveats on that table:

* **`TRUNCATED` is ambiguous.** The notice is a mid-conversation interjection and the
  session continues, so it may mean "one turn was cut" rather than "this role is dead".
  `web_hunt` came back ACCEPTED at `--turns 2` and TRUNCATED at `--turns 6` — the longer
  run didn't get worse, it got *further*. Resolve it by measuring the real thing
  (step 4), not by reading the table harder.
* **Nothing here is a trick for getting past a classifier.** Every model-facing prompt now
  opens with its authorization basis and the swagger is gone, which is more accurate and
  which measurably fixed the planner and two of the proof roles. It was also measured
  *not* to be sufficient on Codex: `web_hunt` was refused with the tool names removed,
  with the win-language removed, and with both removed. When a provider declines a
  workload, the answer is a provider that permits it.

---

## 2. Supply two real identities

An authorization finding is a **comparison between two principals**. Without both, a
"confirmed IDOR" means nothing — the harness never established that the caller shouldn't
have been able to read the thing.

```sh
export P1HUNT_TOKEN_A='<principal A bearer>'
export P1HUNT_TOKEN_B='<principal B bearer>'
```

These become identities `a` and `b`. The shipped client resolves them by name
(`Client.get(path, identity="b")`) and the web authz harness scaffold reads these exact
variable names. Never put a token on the command line or in a scope note — the scope
records the env var *name*, never its value.

---

## 3. Run it

```sh
python3 -m p1hunt.main hunt 'https://target.example' \
  --web --program 'program-name' --platform bugcrowd \
  --live-env bounty \
  --scope-note "$(cat scope.txt)" \
  --max-rounds 3 --live
```

* `--web` is what selects the live black-box methodology and forces `run_mode=active`.
* `--scope-note` is where the program's rules of engagement go. **Put the non-discoverable
  facts here** — a sibling mobile host, a header that selects a variant, which accounts
  you own. The render-gate class of critical is a comparison of two renders of one
  resource; if the thing that selects the second render cannot be found by probing, it has
  to be told.
* `--live` streams the event stream. Without it the output is buffered and you will see
  very little until the end.
* Omit `--max-rounds` to run until a critical is confirmed.

Watch a running hunt from another shell:

```sh
python3 -m p1hunt.main watch engagements/<program-name> --follow
```

### The two HIGH-severity events to watch for

Both mean *stop and fix the setup*, not *the target is clean*:

* **`hunter_roles_refused`** — the provider refused the hunting sessions. This round
  searched for nothing. Switch engines; retrying will not help, a refusal is permanent.
* **`toolchain_broken`** — no harness can execute, so the confirmed count is capped at
  zero regardless of what the hunt finds.

---

## 4. What is measured, and what is not

**Measured — planning.** Against `bench/range_app.py` (9 planted defects, 5 decoys), black
box with no source: **recall 1.000**, all nine found with the correct mechanism, including
the render-gate class a keyword list cannot reach. Precision 0.409, which is low *by
instruction* — the brief says cover the surface, so the plan is a review queue, not a
findings report. 6 of 9 real defects land in the top 9.

**Measured — the proof layer's ceiling.** `tests/test_range_proof_loop.py` hands the real
`WebRunner` hand-written harnesses with no model involved: it reports `reproduced=True` for
the IDOR in both `expect` directions and for the render-gate differential,
`reproduced=False` for a harness aimed at a decoy, and `ran=False` for one that cannot
import. **Given a correct harness, the verdict layer works.**

**NOT measured — the execution loop end to end.** Whether the hunters, handed a plan,
actually write a harness that a runner then confirms. The one real attempt scored 0/9 and
every cause was a pipeline defect rather than a reasoning failure (see
`bench/README.md`). Re-run it with:

```sh
python3 bench/run_exec.py --engine claude
```

Until that produces a non-zero confirmed count, the supportable claim is **"it correctly
identifies what to examine and can prove a bug when handed a correct harness"** — not
"point it at a program and it will find bugs".

**A range is also far denser than a real target.** Nine defects in ~300 lines, no WAF, no
rate limit, no auth wall, no noise. Recall 1.0 there does not transfer, and was never
going to.

---

## 5. Containment, stated plainly

* Every request is confined to the scope's hosts by an egress jail installed on the
  browser context and the shipped HTTP client, and by a `PreToolUse` hook on every shell
  command. Loopback is always allowed (the local OOB listener).
* **Two ceilings you should know about.** A runtime-computed destination (`curl "$URL"`)
  cannot be checked by a command-text blocklist — only a container or VM with firewall
  egress closes that. And `codex-cli` **fails open by design** if its hook malfunctions,
  silently, detectable only after that session's commands have already run. For a target
  where that matters, run the hunt inside a network-isolated container.
* The run never promotes a finding without a reproduced artifact, and never writes an
  unreproduced severity claim into a report.
