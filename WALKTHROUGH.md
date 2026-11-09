# idpdoctor v1 walkthrough (local, ~30 minutes)

Everything below runs on this Mac. Nothing leaves it except the headless Claude calls in steps 6 and 8, which use
your Claude Code login (Max subscription). No API key exists anywhere in this repo; the harness strips
ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN from the environment before every call.

## 0. Build and prove it is green
```sh
cd ~/idpdoctor
make build          # -> ./bin/idpdoctor
make check          # go vet, go test ./..., staticcheck; no real claude call happens in tests
./bin/idpdoctor version
git log --oneline | head   # the commit history is the story you tell in interviews
```
Read while it runs: `docs/TAXONOMY.md` (generated from
`internal/finding/codes.go`, the single source of truth for the 25 failure classes and 8 posture codes).

## 1. Decode a SAML response (what every other tool stops at)
```sh
./bin/idpdoctor saml decode -f testdata/saml/healthy_okta/response.xml
```
Note the NameID comes back as `[REDACTED:nameid:...]`. Redaction is enforced by the type's JSON marshaller, so no
code path can forget it. Try `cat testdata/saml/healthy_okta/response.xml | head -5` to see the raw artifact exists
only on disk, never in output.

## 2. Diagnose a broken one, rules-only (the default; no model involved)
```sh
./bin/idpdoctor diagnose -f testdata/saml/audience_mismatch/response.xml \
  --sp-entity-id https://sp.example.com/saml/metadata --now 2026-01-15T12:00:00Z
echo "exit=$?"    # 2 = fault found, 0 = healthy, 1 = error
```
Read the output top to bottom: top cause, the exact evidence path, actual vs expected, the fix, then the
posture lane (working-but-unsafe findings), then the check table showing what was skipped and what to supply.
Then try with the IdP certificate so signature verification runs:
```sh
python3 -c "import json;print(json.load(open('testdata/saml/audience_mismatch/params.json'))['idp_cert_pem'])" > /tmp/idp.pem
./bin/idpdoctor diagnose -f testdata/saml/audience_mismatch/response.xml \
  --sp-entity-id https://sp.example.com/saml/metadata --now 2026-01-15T12:00:00Z --idp-cert /tmp/idp.pem
```
Other cases worth running: `ls testdata/saml testdata/jwt testdata/oidc testdata/oauth`. Each dir has the
artifact, `params.json` (the expected values), `label.json` (the truth) and `expected.json` (the golden output).

## 3. Mint your own broken assertion
```sh
./bin/idpdoctor eval gen --seed 7 --per-class 1 --controls 2 --out /tmp/mini
ls /tmp/mini/cases | head
cat /tmp/mini/cases/$(ls /tmp/mini/cases | head -1)/label.json
```
The generator mints a signed, healthy response per vendor dialect (Okta, Entra, Google, Keycloak), applies one
mutator per failure class, and verifies the deterministic pipeline agrees with the label before writing the case.

## 4. JWT, OIDC discovery, OAuth errors
```sh
./bin/idpdoctor jwt validate -f testdata/jwt/jwt_expired/token.txt \
  --issuer https://login.example.com/tenant-1/v2.0 --client-id client-abc123 --now 2026-01-15T12:00:00Z
./bin/idpdoctor diagnose -f testdata/oidc/$(ls testdata/oidc | head -1)/artifact.json --now 2026-01-15T12:00:00Z 2>/dev/null || ls testdata/oidc
./bin/idpdoctor diagnose -f testdata/oauth/$(ls testdata/oauth | head -1)/artifact.txt 2>/dev/null || ls testdata/oauth
```
(If a path above does not match, `ls` the dir and use the file it shows; names are per case.)

## 5. The MCP server from Claude Code (agent-first is the product)
The repo's committed `.mcp.json` runs `go run ./cmd/idpdoctor mcp`. From a terminal:
```sh
cd ~/idpdoctor && claude
```
Then in that session: `/mcp` should list `idpdoctor` with 9 tools. Ask it, in plain words:
"Use idpdoctor to diagnose testdata/saml/audience_mismatch/response.xml with SP entity ID
https://sp.example.com/saml/metadata as of 2026-01-15T12:00:00Z." Watch it call `stash_file` and then `diagnose`,
and notice the transcript never contains the raw assertion. The e2e test that does the same over stdio is
`cmd/idpdoctor/mcp_e2e_test.go`.

## 6. `--explain`: the LLM ranks and narrates on top of the validators (1 real call each)
```sh
./bin/idpdoctor diagnose -f testdata/saml/audience_mismatch/response.xml \
  --sp-entity-id https://sp.example.com/saml/metadata --now 2026-01-15T12:00:00Z \
  --symptom "Okta login works but our SP says Invalid audience" --explain --explain-mode tools-on
./bin/idpdoctor diagnose ... --explain --explain-mode tools-off     # same flags; model sees only the redacted summary
```
Each run prints tokens, wall time and the list-price equivalent from the Claude Code envelope. Every cited
evidence path is checked against the parsed summary; anything else is flagged as a hallucinated citation.

## 7. The local-only web page
```sh
./bin/idpdoctor web --addr 127.0.0.1:7777     # then open http://127.0.0.1:7777
./bin/idpdoctor web --addr 0.0.0.0:7777       # refused on purpose
```
Paste the contents of any `testdata/saml/*/response.xml` with the SP entity ID from its params.json.

## 8. The benchmark (this is the README numbers table)
Smoke results already committed: `evals/results/smoke/report.md` (34 cases, plumbing proof, not the benchmark).
Reduced benchmark, 5 per class = 146 cases, about 292 real calls for the two LLM arms (run it when your weekly
usage window has room; it resumes from cache if interrupted):
```sh
./bin/idpdoctor eval gen --seed 42 --per-class 5 --controls 10 --out evals/data/v1-5
./bin/idpdoctor eval run --dataset evals/data/v1-5 --results evals/results/v1-5 \
  --arm rules,llm-tools-off,llm-tools-on --model sonnet --concurrency 1 --max-calls 300
./bin/idpdoctor eval report --results evals/results/v1-5 --dataset evals/data/v1-5 --out evals/results/v1-5/report.md
```

## 9. Your two hours: 50 hand labels (the judge calibration nobody else can do)
After step 8, pick 50 (case, arm) pairs stratified across classes (the report lists them), open each cached result
under `evals/results/v1-5/llm-tools-on-sonnet/` and `.../llm-tools-off-sonnet/`, and score it on `evals/rubric.md`:
`evidence_correct` 1/0 and `fix_score` 1-5, blind to the judge. Append rows to `evals/labels/hand_labels.csv`
(`case_id,arm,evidence_correct,fix_score,notes`), replacing the placeholder rows. Then:
```sh
./bin/idpdoctor eval judge --results evals/results/v1-5 --model opus --labels evals/labels/hand_labels.csv --concurrency 1
./bin/idpdoctor eval report --results evals/results/v1-5 --dataset evals/data/v1-5 --out evals/results/v1-5/report.md
```
The report then carries Cohen's kappa against your labels; paste its tables into README.md and commit. That commit
is v1.0.

## 10. Support bundle (what you would attach to a vendor ticket)
```sh
./bin/idpdoctor bundle --redacted -f testdata/saml/audience_mismatch/response.xml \
  --sp-entity-id https://sp.example.com/saml/metadata --out /tmp/ticket.zip && unzip -l /tmp/ticket.zip
```
No raw artifact inside; `REDACTION.md` explains what was removed and why.

## Interview one-liners this gives you (all true after step 9)
Go MCP server on the official SDK with 9 tools; 25-class published taxonomy; deterministic validators produce every
finding and the LLM only ranks and cites; redaction enforced by type; a fixture IdP that mints signed assertions
in 4 vendor dialects; a three-arm benchmark with a judge calibrated against your own labels; local-only by design,
citing the CVE where a vendor's agent logged decoded assertions.
