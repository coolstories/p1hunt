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
