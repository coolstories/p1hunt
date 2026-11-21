# bench — measuring whether the hunt actually finds bugs

`range_app.py` is a deliberately vulnerable application. **It binds 127.0.0.1 only and
must never be deployed.** It exists so the pipeline can be scored against KNOWN ground
truth on a machine the operator owns, with no third party and nothing to authorize.

It plants **9 real defects** and **5 decoys** that look superficially identical to a
keyword matcher but are correctly implemented. Both numbers matter:

* **recall** — did it find the real ones?
* **precision** — did it leave the decoys alone?

Recall alone is a vanity metric. Triage cost is the real constraint in a bounty
workflow, and a wall of false positives is indistinguishable from noise, so a tool that
reports every endpoint scores 100% recall and is worthless.

The planted set deliberately includes the class a keyword list cannot reach: a **render
gate** applied on one host and missed on another. Nothing about the path, the parameters
or either response in isolation looks wrong — only *comparing two renders* exposes it.
That is the shape of the critical this design was rebuilt around, and it is the single
most important thing the bench measures.

## Running it

    python3 bench/run_range.py --recon-only   # offline, free: what recon alone reaches
    python3 bench/run_range.py                # + a real engine planning pass, then scored

Artifacts land beside the script: `last_surface.json`, `last_brief.txt`, `last_plan.json`,
`last_score.json`.

`--recon-only` reports *location coverage*, not findings: recon measures and does not
judge, so it tells you what the planner gets to reason over, nothing more.

## Measured results

Engine: `gpt-6-astra` at `xhigh`, via the normal `make_session` path. 9 planted defects,
5 decoys.

| mode | hypotheses | recall | precision | precision@9 |
|---|---|---|---|---|
| **black box** (empty cwd, no source) | 25 | **1.000** | 0.409 | 0.667 |
| white box (source readable) | 9 | 1.000 | 1.000 | — |

Black-box rank of each real defect: `secret-session@1, idor-account@2, idor-invoice@4,
gate-host@6, xss-reflect@7, authz-admin@8, ssrf-fetch@11, redirect-open@14, xss-dom@23`.

**Read these numbers carefully.**

* **Black box is the only one that predicts anything.** The first scored run passed the
  bench directory as the session's cwd, the model read `range_app.py`, and its hypotheses
  cited line numbers. It scored 9/9 with zero false positives and was worthless as a
  prediction, because a bounty target has no source to read. Black box is now the default
  and `--whitebox` exists only for the comparison.

* **Overall precision is low BY INSTRUCTION.** The brief says to cover the surface, so
  every endpoint worth reviewing gets an item and roughly 40% of the queue is wasted
  effort. That is the intended trade: the plan is a review queue, not a findings report,
  and the `refute_if` + ledger machinery exists to retire the duds cheaply. `precision@k`
  is the honest measure of a queue, and 6 of the 9 real defects land in the top 9.

* **Confidence is poorly calibrated without source.** Black-box confidences cluster in
  0.26-0.45 against 0.88-0.97 with source. Being less certain is correct; being *flatly*
  less certain is not useful, and it is why the ordering is imperfect (`xss-dom` ranks
  23rd). Do not threshold on confidence in black-box mode.

* **A range is far denser than a real target.** Nine defects in ~300 lines, no WAF, no
  rate limit, no auth wall, no noise. Recall 1.0 here does NOT transfer to a hardened
  production program, and it was never going to.

## What this does NOT measure

Planning only. These numbers say the pipeline **proposes** the right things to look at.
They say nothing about the hunters then EXECUTING the plan: writing a harness, running
the instruments, and producing a reproduced artifact with a verdict. That loop
(plan -> hunter -> harness -> runner verdict) has not been run end to end against the
range, and until it has, "it finds bugs" means "it correctly identifies what to examine".
