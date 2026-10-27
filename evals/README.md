# evals/

The benchmark harness lives in `internal/eval`; this directory holds its
inputs and outputs. See `idpdoctor eval --help` and the README's "Eval"
section.

- `rubric.md`: the judge prompt (BUILD_PLAN 6.3).
- `symptom_templates/`: vendor error strings and, later, anonymized Spear
  templates (see its README).
- `labels/hand_labels.csv`: human scores for the judge calibration (kappa).
- `data/<name>/cases/<id>/`: generated datasets (`eval gen`), committed when
  small so numbers are reproducible.
- `results/<name>/<arm>[-<model>]/<case hash>.json`: cached arm results
  (`eval run`); LLM-arm results and manifests carry `prompt_version`
  (`agent.PromptVersion`), and a cached result from another prompt version
  is re-run; `results/<name>/judge-<model>/...`: judge verdicts;
  `results/<name>/report.md` + `summary.json` (`eval report`).
- `results/smoke/`: the v1 smoke run (prompt v1, all three arms, judge).
  `results/smoke-v2/`: the tools-on arm re-run with prompt v2 (allowed-path
  list, schema enum, check-name normaliser); `rules/`,
  `llm-tools-off-sonnet/` and the tools-off judge verdicts are copied from
  `smoke/` unchanged so `eval report` renders the full table. The tools-on
  arm there has no judge verdicts.

Nothing under `results/` contains an artifact: outputs are the redacted
diagnosis, the label, usage numbers and the CLI envelope.
