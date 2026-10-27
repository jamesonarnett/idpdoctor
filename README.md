# idpdoctor

Decode, validate and diagnose SAML / JWT / OIDC artifacts, locally, from a CLI or from an agent via MCP.

`idpdoctor` is for the developer on the **service-provider side** of an enterprise SSO integration: the one
holding a captured SAML Response or id_token that an IdP (Okta, Entra, Google, Ping, ADFS, Keycloak...) issued,
and a vague error from their own library. It runs every applicable check, never stops at the first failure, and
returns machine-readable findings with evidence paths and a vendor-neutral fix. The same validators power the
CLI and the MCP server, so a Claude Code or Cursor session can call `saml_validate` mid-debug.

Status: **v0 deterministic core + MCP server, first slice complete** (2026-10-27). 16 of the 25 catalog
classes are caught deterministically (SAML #1-11, JWT/OIDC #14-18), plus 7 of the 8 posture codes. No LLM
code exists in this tree; `idpdoctor diagnose` is rules-only and must stay fully useful that way. The
benchmark table and the `--explain` layer are v1.

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
idpdoctor mcp                                            # MCP server over stdio
```

`--now` replays a capture at its capture time. `diagnose` exits 2 when a fault-lane error was found, 0 when
the artifact validates (posture warnings do not change the exit code), 1 on usage or decode errors. Every
check that lacks its expected value reports `skip` and the output ends with `Supply to unskip checks: ...`.

Try it on a committed fixture:

```sh
make build
./bin/idpdoctor diagnose -f testdata/saml/audience_mismatch/response.xml \
    --sp-entity-id https://sp.example.com/saml/metadata --now 2026-01-15T12:00:00Z
```

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

Tools (v0): `saml_decode`, `saml_validate`, `jwt_decode`, `jwt_validate`, `cert_inspect`, `diagnose`,
`stash_file`. A typical agent session: `stash_file {"path": "capture.txt"}` -> `diagnose {"input_ref":
"art_...", "expected": {"sp_entity_id": "..."}}` -> read `needs`, ask the human, call `saml_validate` with
the fuller `expected`. Every artifact parameter is either `input` (inline) or `input_ref` (an opaque handle returned by
`stash_file`), so an agent can work on an assertion it has never seen in its own context. Every response carries
`"redaction": "default"`; there is no parameter that turns redaction off.

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
| Local only | No telemetry. No network unless a tool is explicitly given a `jwks_url` / `issuer_url`. |

Tests enforce the first rule: a test mints fixtures with known NameID and attribute values and asserts that none of
them appear in any tool output.

## Prior art

Two zero-star hobby attempts appeared in Aug-Sep 2026: [codecheesee/sso-doctor](https://github.com/codecheesee/sso-doctor)
and ClavionX SAML Debugger. Both are PASS/WARN/FAIL rule checkers with no signature verification, no OIDC/OAuth
breadth, no evaluation numbers and no MCP surface. idpdoctor v0 covers all four: XML-DSig verification against a
supplied IdP cert via goxmldsig, JWT/JWKS validation with an alg allow-list, a published taxonomy with a
benchmark table to follow in v1, and an MCP server built on the official Go SDK.

Tools this builds on rather than replaces: [SAML-tracer](https://github.com/SimpleSAMLphp/SAML-tracer) and the
SAML Chrome Panel (capture), [OneLogin's tools](https://developers.onelogin.com/docs/saml/online-tools/) and jwt.io
(single-purpose verify, hosted), [ory/mocksaml](https://github.com/ory/mocksaml) (a healthy test IdP; it cannot emit
bad responses, which is why this repo mints its own), and the SP libraries whose error strings double as oracles
for the fixture set: crewjam/saml, gosaml2, python3-saml, node-saml, go-oidc, Microsoft.IdentityModel.

| | sso-doctor / ClavionX | idpdoctor |
|---|---|---|
| Signature verification | no | yes (goxmldsig >= 1.6.1, verify-before-decrypt) |
| OIDC + OAuth | no | JWT/JWKS in v0; discovery and OAuth error explain in v1 |
| Benchmark | none | v1: N fixtures, root-cause accuracy, per-class confusion matrix |
| MCP | no | yes, official go-sdk, stdio |
| Posture lane | no | yes, always on |

## Development

```sh
make build                              # ./bin/idpdoctor
make check                              # go vet, go test, staticcheck (pinned v0.8.2)
make generate                           # re-render docs/TAXONOMY.md from codes.go
go test ./internal/diag -update         # regenerate testdata/{saml,jwt}/<case>/ from the fixture mutators
```

Layout follows BUILD_PLAN 2.1: `cmd/idpdoctor` (cobra, adapters only), `internal/finding` (types + catalog),
`internal/redact` (policy + handle store), `internal/saml`, `internal/jwt`, `internal/cert`, `internal/expected`,
`internal/fixture` (in-process test IdP and mutators), `internal/diag` (pipeline), `internal/mcpserver` (go-sdk
adapters). Nothing under `internal/` imports `cmd/` or `mcpserver`; the only network call in the product is
`jwt_validate` with `jwks_url`. Tests make no network calls (`httptest` only). Every fixture is synthetic and
minted by the repo; the committed keys in `internal/fixture/testkey.go` are TEST ONLY.

Fixture engine decision: assertions are signed with goxmldsig `SignEnveloped` on an etree template rather
than crewjam's IdP (BUILD_PLAN 8.6 option b), which keeps a dormant dependency out and gives direct control
over which element is signed.

See [LEARNING.md](LEARNING.md) for a reading order through the code and the Go concepts each package exercises.

## License

Apache-2.0. See [LICENSE](LICENSE).
