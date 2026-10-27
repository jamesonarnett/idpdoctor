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
  (`eval run`); `results/<name>/judge-<model>/...`: judge verdicts;
  `results/<name>/report.md` + `summary.json` (`eval report`).

Nothing under `results/` contains an artifact: outputs are the redacted
diagnosis, the label, usage numbers and the CLI envelope.
