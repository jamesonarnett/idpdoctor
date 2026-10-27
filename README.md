# idpdoctor

Decode, validate and diagnose SAML / JWT / OIDC artifacts, locally, from a CLI or from an agent via MCP.

`idpdoctor` is for the developer on the **service-provider side** of an enterprise SSO integration: the one
holding a captured SAML Response or id_token that an IdP (Okta, Entra, Google, Ping, ADFS, Keycloak...) issued,
and a vague error from their own library. It runs every applicable check, never stops at the first failure, and
returns machine-readable findings with evidence paths and a vendor-neutral fix. The same validators power the
CLI and the MCP server, so a Claude Code or Cursor session can call `saml_validate` mid-debug.

Status: **v1: agent + eval harness, smoke-tested on the real subscription** (2026-10-27). 24 of the 25
catalog classes have a validator, a fixture mutator and a golden case (SAML #1-12, JWT/OIDC #14-20, OAuth
#21-25; #13 encrypted assertions is v2), and all 8 posture codes do. `idpdoctor diagnose` is rules-only by
default and stays fully useful that way; `--explain` adds one headless Claude Code call that narrates the same
findings and must cite a parsed field per claim. The benchmark table below comes from a 146-case run; judge agreement is pending hand labels.

## Why this exists

Nobody ships artifact-in, diagnosis-out. Browser extensions capture and decode; online tools verify one signature;
SP libraries bury the reason (crewjam/saml's public error is always "Authentication failed", node-saml ships
clock skew 0 and only logs Destination/Recipient mismatches, python3-saml stops at the first failure). Every IdP
diagnoses only what it issued; every SP platform validates only what it received. idpdoctor is the cross-vendor,
SP-side tool in between.

Five positioning rules, all of them enforced by code rather than by intent:

1. **Published failure taxonomy.** `internal/finding/codes.go` is the single source of truth for the 25 failure
   classes and 8 security-posture codes; `go generate` renders [docs/TAXONOMY.md](docs/TAXONOMY.md) from it,
   including the vendor error codes each class was merged from (Scalekit, WorkOS, the SAML-flavoured AADSTS
   codes, Google, Snowflake, GitLab). A reproducible benchmark table lands here in v1.
2. **Deterministic validators produce every finding.** The LLM (v1) only ranks and narrates and must cite a parsed
   field per claim. `idpdoctor diagnose` with no flags is `--no-llm`.
3. **Local-only, redact-by-default, zero-persistence.** See the threat model below.
4. **Cross-vendor, SP-side, with a security-posture lane.** Findings carry `lane: fault` (it is broken) or
   `lane: posture` (it works but is unsafe). The posture lane is always on.
5. **Prior art is named**, below, with what it lacks and what this tool adds.

## Install

```sh
go install github.com/jamesonarnett/idpdoctor/cmd/idpdoctor@latest   # once the repo is public
# or, from a checkout:
make build && ./bin/idpdoctor version
```

Release archives are built by GoReleaser v2 (`.goreleaser.yaml`, linux/darwin/windows, amd64/arm64). The
release workflow only runs `goreleaser check` and a `--snapshot --skip=publish` build that uploads the archives
as workflow artifacts; publishing is a manual, credentialed step this repo does not perform. For `--explain`
and `eval` you also need the Claude Code CLI (`claude`) logged in to a Max or Pro subscription; no API key is
ever read.

## CLI

```sh
idpdoctor saml decode   -f response.b64                  # any binding; redacted pretty XML (--json for the summary)
idpdoctor saml validate -f response.b64 --sp-entity-id https://sp.example.com/saml/metadata \
    --acs-url https://sp.example.com/saml/acs --idp-entity-id https://idp.example.com/saml \
    --idp-cert idp.pem --request-id _req123 --required-attr email --require-signed-assertion
idpdoctor jwt decode    -f id_token.txt
idpdoctor jwt validate  -f id_token.txt --issuer https://login.example.com/t/v2.0 --client-id my-client --jwks jwks.json
idpdoctor cert inspect  -f idp.pem
idpdoctor diagnose      -f response.b64 --sp-entity-id ... --acs-url ... [--now 2026-01-15T12:00:00Z] [--json]
idpdoctor diagnose      -f openid-configuration.json --issuer https://login.example.com/t/v2.0      # discovery doc
idpdoctor diagnose      -f redirect.txt --redirect-uri https://app/cb --registered-redirect-uri https://app/cb \
    --code-verifier ... --code-challenge ... --code-challenge-method S256 --client-type public      # OAuth error
idpdoctor diagnose      -f response.b64 --sp-entity-id ... --explain [--explain-mode tools-on|tools-off] [--model sonnet]
idpdoctor bundle --redacted -f response.b64 --out ticket.zip --sp-entity-id ...   # support-ticket export, never the raw artifact
idpdoctor web           [--addr 127.0.0.1:7777]          # local-only paste-and-diagnose page
idpdoctor mcp                                            # MCP server over stdio
idpdoctor eval gen|run|judge|report                      # benchmark harness (see Eval below)
```

`--now` replays a capture at its capture time. `diagnose` exits 2 when a fault-lane error was found, 0 when
the artifact validates (posture warnings do not change the exit code), 1 on usage or decode errors. Every
check that lacks its expected value reports `skip` and the output ends with `Supply to unskip checks: ...`.
`diagnose` sniffs SAML responses (any binding), JWTs, certificates, OIDC discovery documents, OAuth error
redirects and token-endpoint error bodies.

Try it on a committed fixture:

```sh
make build
./bin/idpdoctor diagnose -f testdata/saml/audience_mismatch/response.xml \
    --sp-entity-id https://sp.example.com/saml/metadata --now 2026-01-15T12:00:00Z
```

### `--explain`: one headless Claude Code call, subscription only

`--explain` runs `claude -p` (Claude Code CLI, tested with 2.1.311) as a subprocess with a scrubbed
environment: `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL` and the `CLAUDE_CODE_USE_*`
provider switches are removed, so the CLI can only use your `/login` (Max/Pro) credentials and nothing can
route to API billing. The exact flag set (`internal/agent/runner.go`):

```
claude -p --output-format json --json-schema <diagnosis schema> --model sonnet --system-prompt <rules + catalog>
       --tools "" --setting-sources "" --strict-mcp-config --no-session-persistence --permission-mode dontAsk
       --max-turns <planned tool calls + 2> --max-budget-usd 1.00
       [--mcp-config <tmp>/mcp.json --allowedTools "mcp__idpdoctor__*"]        # tools-on only
```

The prompt goes on stdin; the child runs in an empty temp dir so no `CLAUDE.md` or `.mcp.json` is picked up.
Two modes:

| Mode | What the model sees | Tools |
|---|---|---|
| `tools-on` (default) | an opaque `input_ref` handle, the symptom, `expected` (access token masked) | idpdoctor's own MCP server, started by the CLI with the file preloaded (`idpdoctor mcp --preload <file>`); the artifact never enters the transcript |
| `tools-off` | the **redacted** structure (NameID, attribute values, PII claims, signature values masked), the symptom, `expected` | none |

The model must return the structured object `{root_cause_code, confidence, evidence[{path, actual, ...}],
fix, posture_codes, alternatives, questions}`. The user turn enumerates the **allowed evidence paths** for this
artifact (the validators' evidence plus its parsed structure, `diag.KnownPaths`), with one correct and two
incorrect examples, and the schema makes `evidence[].path` an enum of exactly that list, so the CLI's
structured-output enforcement rejects a check name or a paraphrased path. In tools-on mode every tool result
ends with `Evidence paths (cite verbatim in evidence[].path): ...`. After parsing, an exact check-name citation
(`audience`, `checks/audience`) is normalised to its one canonical path only when `diag.CheckPaths` maps it
unambiguously (`note: cited "checks/audience", a check name, shown above as ...`); anything else not on the list
is a hallucinated citation (`WARNING: n cited path(s) not present`), and the deterministic findings are always
printed first and never overridden. The envelope's `usage`, `num_turns`,
`duration_ms` and `total_cost_usd` (list-price basis; nothing is billed) are printed on the last line, and any
`permission_denials` fail the call. Tests never call the real CLI: a fake `claude` on `PATH` emits canned
envelopes; `go test -tags live ./internal/agent -run Live` makes exactly one real call.

## MCP

Add to a project's `.mcp.json` (Claude Code) or the equivalent in Cursor. With the binary on `PATH`:

```json
{
  "mcpServers": {
    "idpdoctor": {
      "command": "idpdoctor",
      "args": ["mcp"]
    }
  }
}
```

From a checkout without installing (this is the committed `.mcp.json` in this repo):

```json
{
  "mcpServers": {
    "idpdoctor": {
      "command": "go",
      "args": ["run", "./cmd/idpdoctor", "mcp"]
    }
  }
}
```

The server prints one line to stderr on start and nothing else; stdout is the protocol channel. It is
verified end to end by `cmd/idpdoctor/mcp_e2e_test.go`, which builds the binary, launches `idpdoctor mcp`
with the go-sdk `CommandTransport`, lists the tools and calls `saml_decode` on a minted fixture.

Tools:

| Tool | Input (all artifact fields accept `input_ref`) | Output |
|---|---|---|
| `saml_decode` | `input`, `binding` | binding, redacted pretty XML, summary (issuer, status, audience, NameID presence/format, conditions, signatures, attribute names) |
| `saml_validate` | `input`, `expected` | `ok`, 14 checks, findings, `needs`, summary |
| `jwt_decode` | `token` | header, redacted claims, kind guess, time to expiry, header red flags |
| `jwt_validate` | `token`, `expected`, `keys{jwks_json\|jwks_url\|pem}` | `ok`, checks (alg, kid, signature, iss, aud, azp, exp, nbf, iat, nonce, at_hash), findings |
| `cert_inspect` | `cert`, `now` | subject, validity, key size, fingerprints, findings |
| `oidc_discovery_check` | `document_json` or `issuer_url` (the one fetch), `expected_issuer` | summary (issuer, endpoints, algs), checks (required_fields, issuer_match, https_only, rs256_present, endpoint_hosts, token_endpoint, content_type), findings |
| `oauth_error_explain` | `redirect_url` or `error_body_json`, `request{redirect_uri, registered_redirect_uris, code_verifier, code_challenge, code_challenge_method, scopes, response_type, grant_type, client_type}` | error, vendor code (AADSTS / Okta), vendor, checks (error_class, redirect_uri, pkce, pkce_posture, client_config), findings; codes and verifiers are never echoed |
| `diagnose` | `artifact`, `artifact_kind`, `symptom`, `expected`, `keys` | ranked findings, `top_cause`, checks, `needs` (deterministic) |
| `stash_file` | `path` | `input_ref`, kind, byte count, redacted preview |

A typical agent session: `stash_file {"path": "capture.txt"}` -> `diagnose {"input_ref": "art_...", "expected":
{"sp_entity_id": "..."}}` -> read `needs`, ask the human, call `saml_validate` with the fuller `expected`. Every
artifact parameter is either `input` (inline) or `input_ref` (an opaque handle returned by `stash_file`), so an
agent can work on an assertion it has never seen in its own context. Every response carries
`"redaction": "default"`; there is no parameter that turns redaction off. `idpdoctor mcp --preload <file>`
registers a file under its deterministic handle before the first request (this is how `--explain` and the eval
hand the agent a handle), and `$IDPDOCTOR_TRACE=<file>` appends one JSON line per tool call (tool name, duration,
finding codes; never inputs) for the eval's tool-call count.

## Web page (local only)

`idpdoctor web` serves one embedded vanilla HTML page and `POST /api/diagnose` on `127.0.0.1:7777`. It refuses
any non-loopback `--addr` (`0.0.0.0`, `:8080`, a LAN IP) before opening a socket, rejects requests whose `Host`
is not loopback, logs nothing (not even `net/http`'s own errors), stores nothing, sets `Cache-Control: no-store`
and a strict CSP, and returns the same redacted output as `diagnose`. Never deploy it; it is a desktop
convenience for people who would otherwise paste an assertion into a hosted decoder.

## Eval

The benchmark harness (`internal/eval`, inputs and outputs under [`evals/`](evals/README.md)):

```sh
idpdoctor eval gen    --seed 42 --per-class 10 --controls 30 --out evals/data/v1        # labelled synthetic dataset
idpdoctor eval run    --dataset evals/data/v1 --arm rules,llm-tools-off,llm-tools-on --model sonnet --concurrency 2
idpdoctor eval judge  --results evals/results/v1 --model opus --labels evals/labels/hand_labels.csv
idpdoctor eval report --results evals/results/v1 --dataset evals/data/v1 --out evals/results/v1/report.md
```

`gen` mints N cases per catalog class across the four SAML dialects (generic, Okta, Entra, Auth0), rotates the
mutator variants, draws symptom text from `evals/symptom_templates/*.json` (vendor strings now; Jameson's
anonymized Spear templates later, see that directory's README), withholds expected values on a schedule
(full / partial / none) so abstention is measured, adds healthy controls (a third with a misleading symptom)
and one validating fixture per posture code labelled `HEALTHY` + `posture_codes`. Every fault case is checked
against the deterministic pipeline at generation time, so a label is always the validators' own truth. `run`
caches each result under `evals/results/<name>/<arm>[-<model>]/<case hash>.json`, so a stopped run resumes
for free; `--max-calls` is a hard cap on real calls. `judge` scores evidence correctness (0/1), fix usefulness
(1-5) and `fix_is_security_regression` with `opus` (a different model than the diagnoser) using
[`evals/rubric.md`](evals/rubric.md), and reports Cohen's kappa (binary) plus quadratic weighted kappa (fix
score) against the hand labels. `report` renders this table:

| Arm | Root-cause acc. | Top-2 | FP rate (controls) | Evidence correct (judge) | Fix score (1-5) | p50 / p95 latency | Tool calls/case | Tokens/case (in / out) | List-price equiv./case |
|---|---|---|---|---|---|---|---|---|---|
| rules-only | 100.0% | 100.0% | 0.0% | n/a | n/a | 0.0s / 0.0s | 0.0 | 0 / 0 | $0.0000 |
| LLM, tools off (sonnet) | 88.3% | 97.7% | 8.0% | n/a | n/a | 7.7s / 14.7s | 0.0 | 9102 / 946 | $0.0280 |
| LLM, tools on (sonnet) | 99.2% | 100.0% | 4.0% | n/a | n/a | 11.9s / 17.8s | 1.0 | 31760 / 1547 | $0.0424 |

Dataset: 146 cases = 24 fault classes x 5 (one class has fewer minted variants) + 10 healthy controls + 16 posture
fixtures, seed 42, generated by `idpdoctor eval gen` (`evals/data/v1-5`). Diagnoser: sonnet via Claude Code 2.1.311
headless, prompt v2. 258 real model calls. Judge columns are n/a until the 50 hand labels exist (BUILD_PLAN 6.3);
per-class confusion matrices per arm: [`evals/results/v1-5/report.md`](evals/results/v1-5/report.md).

| Arm | Hallucinated citations | Normalised citations | Unsafe fixes (judge or regex) | Posture recall | Abstention quality | Errors |
|---|---|---|---|---|---|---|
| rules-only | 0.0% (131 cited) | 0.0% | n/a (0 judged) | 100.0% (16 cases) | n/a (0 cases) | 0 |
| LLM, tools off (sonnet) | 0.0% (492 cited) | 0.0% | n/a (0 judged) | 75.0% (16 cases) | n/a (0 cases) | 0 |
| LLM, tools on (sonnet) | 0.0% (229 cited) | 0.0% | n/a (0 judged) | 100.0% (16 cases) | n/a (0 cases) | 0 |

How to read this honestly. The fixtures are minted by the same validators that score them, so the rules-only row
is a self-consistency check, not evidence that the rules catch every real-world failure. The comparison that means
something is between the two LLM rows: the same model, the same redacted artifact, with and without idpdoctor's
tools. Tools took root-cause accuracy from 88.3% to 99.2%, posture recall from 75% to 100%, and halved the
false-positive rate on healthy controls, at about 3.5x the input tokens. Tools-off misses were concentrated where
the raw structure does not carry the answer: `alg=none`/confusion, audience versus `azp`, discovery-document
validity, at_hash binding, and the SAML status code. Hallucinated citations are 0% in all arms after prompt v2
(the model is given the artifact's allowed evidence paths and the schema enforces them); the 34-case prompt-v1
smoke run (`evals/results/smoke/`) had 20.3% for tools-on and is kept for comparison.

Every number above is pasted from `eval report` output, never typed by hand.
`report` also emits hallucinated-citation rate (cited paths not on the artifact's allowed list after
normalisation), normalised-citation rate (exact check-name citations mapped to their canonical path; counted on
their own, never as correct), unsafe-fix rate (judge verdict or the banned-phrase regex), posture recall,
abstention quality and a per-class confusion matrix per arm. A 34-case smoke run (1 per class) is committed
under `evals/results/smoke/` (prompt v1) to prove the plumbing, and `evals/results/smoke-v2/` re-runs the
tools-on arm with prompt v2 (allowed-path list + schema enum) next to the unchanged rules and tools-off results;
the judge calibration uses 8 placeholder labels written by the harness author, not hand labels, and the report
says so. The cache key is the case hash **and** `agent.PromptVersion`: `run` stamps `prompt_version` into every
LLM-arm result and manifest and re-runs a cached case whose version differs (printed as `stale`), so a results
directory never silently mixes prompts. Bump the constant whenever the prompt or schema changes.

## Threat model: local-only, redact-by-default, zero-persistence

A SAML assertion is a bearer credential carrying PII; an id_token is the same. Pasting one into a hosted decoder,
an LLM chat window or a support ticket is exactly how they leak:

- Okta's own Hyperdrive agent shipped CWE-532 (CVE-2026-78631): decoded SAML bearer assertions written to a
  local log at the default level, fixed in 1.5.2
  ([advisory](https://trust.okta.com/security-advisories/improper-restriction-of-sensitive-information-in-okta-hyperdrive-agent-logging-cve-2026-78631)).
  An LLM transcript or a pasted web form reproduces that failure.
- Spring Security decrypted before verifying signatures (CVE-2026-41694,
  [spring.io](https://spring.io/security/cve-2026-41694)). idpdoctor verifies before it ever decrypts, and the
  posture lane flags SP configurations that do not.
- AWS's IAM troubleshooting guide decodes captured responses locally with `base64`
  ([docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_saml_view-saml-response.html)); "never
  paste a production assertion into an online decoder" is **our** policy, stated as such.
- OneLogin's online-tools page warns against using production keys with hosted tools
  ([developers.onelogin.com](https://developers.onelogin.com/docs/saml/online-tools/)).

What idpdoctor does about it:

| Rule | Mechanism |
|---|---|
| Redact before anything leaves the process | `internal/redact` replaces NameID values, every AttributeValue, PII-class JWT claims (`sub`, `email`, `name`, `preferred_username`, `upn`, `oid`...), `SignatureValue`, `CipherValue`, secrets and raw tokens with `[REDACTED:<kind>:<sha256 prefix>]`. Entity IDs, URLs, timestamps, formats, algorithms, `kid`, cert fingerprints, status codes and attribute **names** stay in clear because diagnosis needs them and they are not PII. Equality checks (NameID == expected) run server-side and report `match: true/false`, never the value. |
| Assertions never enter an agent transcript | Artifact handles. The developer saves the capture to a file; the agent calls `stash_file {path}` and gets back an opaque `input_ref`; every tool accepts `input_ref`. The server reads the file locally and the model only ever sees redacted summaries. |
| No off switch | Redaction is a property of every output, not a flag. No tool parameter and no CLI flag disables it. |
| Zero persistence | No temp files, no caches, no session logs. The CLI writes nothing unless `--out` is given. |
| Fix advice is never a security regression | Fix templates live in `codes.go` and never say "disable signature validation", "accept unsigned" or "raise clock skew above 5 minutes". |
| Local only | No telemetry. No network unless a tool is explicitly given a `jwks_url` / `issuer_url`. The web page binds loopback only. |
| The model never sees the artifact | `--explain` tools-on passes a handle; tools-off passes the redacted structure; the eval's tools-off arm is the only place artifact text (redacted) enters a transcript. `access_token` is masked in prompts; PKCE values are single-use and stay in clear. The prompt text is covered by the no-leak tests. |
| Support tickets | `bundle --redacted` is the only export: findings, redacted summary and structure, params with the access token and verifier masked, a manifest with the artifact's SHA-256, and `REDACTION.md`. Signature values are masked, so nothing in the zip replays. |
| Subscription only | `claude` is run with `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` stripped from its environment; `--max-budget-usd` is a client-side guard and `total_cost_usd` is a list-price equivalent, not a bill. |

Tests enforce the first rule: a test mints fixtures with known NameID and attribute values and asserts that none of
them appear in any tool output.

## Prior art

Two zero-star hobby attempts appeared in Aug-Sep 2026: [codecheesee/sso-doctor](https://github.com/codecheesee/sso-doctor)
and ClavionX SAML Debugger. Both are PASS/WARN/FAIL rule checkers with no signature verification, no OIDC/OAuth
breadth, no evaluation numbers and no MCP surface. idpdoctor v0 covers all four: XML-DSig verification against a
supplied IdP cert via goxmldsig, JWT/JWKS validation with an alg allow-list, a published taxonomy with a
reproducible benchmark harness, and an MCP server built on the official Go SDK.

Tools this builds on rather than replaces: [SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) and the
SAML Chrome Panel (capture), [OneLogin's tools](https://developers.onelogin.com/docs/saml/online-tools/) and jwt.io
(single-purpose verify, hosted), [ory/mocksaml](https://github.com/ory/mocksaml) (a healthy test IdP; it cannot emit
bad responses, which is why this repo mints its own), and the SP libraries whose error strings double as oracles
for the fixture set: crewjam/saml, gosaml2, python3-saml, node-saml, go-oidc, Microsoft.IdentityModel.

| | sso-doctor / ClavionX | idpdoctor |
|---|---|---|
| Signature verification | no | yes (goxmldsig >= 1.6.1, verify-before-decrypt) |
| OIDC + OAuth | no | JWT/JWKS, discovery check, OAuth error explain, PKCE verification |
| Benchmark | none | `idpdoctor eval`: three arms, LLM judge with kappa, per-class confusion matrix (146-case run committed; kappa pending hand labels) |
| MCP | no | yes, official go-sdk, stdio |
| Posture lane | no | yes, always on |

## Development

```sh
make build                              # ./bin/idpdoctor
make check                              # go vet, go test, staticcheck (pinned v0.8.2); no real claude calls
make generate                           # re-render docs/TAXONOMY.md from codes.go
go test ./internal/diag -update         # regenerate testdata/{saml,jwt,oidc,oauth}/<case>/ from the fixture mutators
go test -tags live ./internal/agent -run Live -v   # the one opt-in real claude -p call
```

Layout follows BUILD_PLAN 2.1: `cmd/idpdoctor` (cobra, adapters only), `internal/finding` (types + catalog),
`internal/redact` (policy + handle store), `internal/saml`, `internal/jwt`, `internal/oidc`, `internal/oauth`,
`internal/cert`, `internal/expected`, `internal/fixture` (in-process test IdP and mutators for every kind),
`internal/diag` (pipeline, known-path set, redacted text), `internal/mcpserver` (go-sdk adapters, trace,
preload), `internal/agent` (headless `claude -p`, prompts, schema, citation check), `internal/eval` (gen, run,
judge, kappa, report), `internal/bundle`, `internal/web`. Nothing under `internal/` imports `cmd/`; only
`agent` imports `mcpserver` (for the output cap constant). The only network calls in the product are
`jwt_validate` with `jwks_url` and `oidc_discovery_check` with `issuer_url`. Tests make no network calls
(`httptest` only) and never run the real `claude` (`internal/agent/agenttest` puts a fake on `PATH`). Every
fixture is synthetic and minted by the repo; the committed keys in `internal/fixture/testkey.go` are TEST ONLY.

Fixture engine decision: assertions are signed with goxmldsig `SignEnveloped` on an etree template rather
than crewjam's IdP (BUILD_PLAN 8.6 option b), which keeps a dormant dependency out and gives direct control
over which element is signed.

Decisions recorded while building v1 (where the plan met a real API):

- The Claude Agent SDK is not used (it cannot use a subscription login); the harness drives the unmodified CLI
  with `-p`, exactly as BUILD_PLAN 5.2 verified. The prompt is passed on stdin rather than as an argument so it
  never appears in `ps` output; the system prompt goes through `--system-prompt`.
- `--max-turns` is budgeted as planned tool calls + 2 because `--json-schema` costs an extra turn.
- An expired signing certificate whose signature still verifies is a `warn` plus `POSTURE_EXPIRED_CERT_ACCEPTED`
  (v0 behaviour, kept); the eval therefore uses the committed 1024-bit key (`cert_weak_key`) as class 11's fault
  case and `cert_expired` stays a posture fixture.
- Posture fixtures are labelled `HEALTHY` + `posture_codes`; the eval's `truth` self-check runs every generated
  fault case through the pipeline and refuses to emit a label the validators would not produce.
- `goreleaser check` could not be run on the build machine (binary not installed, and running the module via
  `go run` was not permitted); the release workflow runs it in CI.
- The v1 smoke run hallucinated citations 20.3% (tools-on) / 27.0% (tools-off) of the time, almost all check
  names (`checks/audience`) or paraphrased paths rather than the exact evidence paths the validators returned.
  Fixed at the source, not in the metric: the prompt enumerates the allowed paths with examples, the schema
  constrains `evidence[].path` to that enum per call (Claude Code 2.1.311 enforces it), tool results print
  their evidence paths on a labelled line, and a post-parse normaliser maps an exact check name to its canonical
  path only when unambiguous, reported as "normalised", never as correct. `agent.PromptVersion` joined the cache
  key so the v1 results could not be reused by accident.

See [LEARNING.md](LEARNING.md) for a reading order through the code and the Go concepts each package exercises.

## License

Apache-2.0. See [LICENSE](LICENSE).
