# Learning Go through idpdoctor

This is the reading order for someone new to Go who has to own every package in an interview. Read the
packages in the order below: each one leans only on the ones before it. For each package there is a note
on the Go concepts it exercises and three exercises to do by hand, without Claude Code. Do them in a
scratch branch; the tests tell you when you are right.

Before starting: `go version` (1.27 on this machine; `go.mod` says `go 1.25.0`, the minimum the module
promises to compile with), `make check`, and read `go.mod` + `go.sum` once. `go.sum` is a lockfile of
hashes, not a dependency list; `go mod tidy` rewrites both.

Packages added in v1 (`agent`, `eval`, `oidc`, `oauth`, `bundle`, `web`) are sections 10-13; they lean on
everything before them, so finish 1-9 first.

## 0. `cmd/idpdoctor` (skim first, read last)

`main.go` is twelve lines: build a signal-aware `context.Context`, run the cobra root with
`ExecuteContext`, map errors to exit codes. Everything else in this directory is adapters. Skim it now to
see the shape, come back after the internals make sense.

Concepts: `package main`, `os.Exit`, `signal.NotifyContext`, `errors.As` to pull a typed `exitError` out of
whatever cobra returned.

## 1. `internal/finding` — the vocabulary

Read `finding.go`, then `codes.go`, then `render.go`, then `gen/main.go`, then `codes_test.go`.

Concepts:
- Named string types (`type Severity string`) with constants: Go's enum idiom. Note that `Lane("x")` is a
  legal value; the type is documentation plus method attachment, not a closed set.
- A package-level slice of structs as data (`Catalog`). The whole taxonomy is a Go literal; `go generate`
  turns it into markdown. Look at the `//go:generate` directive in `codes.go` and the `TestTaxonomyDocInSync`
  test that fails when the doc is stale: the test is the sync mechanism, the generator is the convenience.
- `sort.SliceStable` with a multi-key comparator (`Sort`).
- `panic` for programmer errors (`New` with an unknown code) vs returned errors for runtime conditions.
- Struct tags: `json:"code"` controls encoding; `omitempty` matters later for JSON schemas.

Exercises:
1. Add a ninth posture code to `Catalog`, run `go test ./internal/finding`, read the two failures, run
   `go generate ./...`, run the tests again. Then remove it. Explain which test failed first and why.
2. Write a table-driven test for `Severity.rank` (unexported, so the test must be `package finding`).
3. Change `Sort` so posture findings come first and watch `TestSortOrder` fail; read the diff output and put
   it back.

## 2. `internal/redact` — the threat model as code

Read `redact.go`, `handles.go`, `redact_test.go`.

Concepts:
- `crypto/sha256`, `encoding/hex`, deterministic masking (`Value`).
- Recursion over a tree (`XML`), and why it matches on the local name only.
- Type switches (`maskAny`) over `any` (the alias for `interface{}`).
- `sync.Mutex` protecting a map in `Store`; why `Get` returns a copy; why handles come from
  `crypto/rand`, not `math/rand`.
- Test helpers via `t.Run` subtests and a `tests := []struct{...}` table.

Exercises:
1. Add `"birthdate"` to `jwtSensitive` and write the test that proves it is masked.
2. Write a benchmark `BenchmarkValue` and run `go test -bench . ./internal/redact`.
3. Make `Store.Put` return an error if the store already holds 1000 artifacts; test it.

## 3. `internal/cert` — stdlib crypto

Read `inspect.go`, `inspect_test.go`.

Concepts:
- `encoding/pem` and `crypto/x509`; `x509.ParseCertificate` accepts SHA-1 certs even though `Verify`
  would reject them, which is exactly what a diagnostic tool wants.
- Wrapping errors with `%w` so callers can `errors.Is(err, ErrNoCertificate)` whatever the cause.
- Minting a self-signed cert in a test (`x509.CreateCertificate`): the test is its own fixture factory.
- `[20]byte` arrays vs `[]byte` slices (`Fingerprint(sha1.Sum(...))`).

Exercises:
1. Add `KeyUsage` reporting to `Info` and a test that the fixture cert has `DigitalSignature`.
2. Write a test that `Parse` of a PEM file containing a PRIVATE KEY block followed by a CERTIFICATE block
   still returns the certificate.
3. Explain, in a comment, why `Inspect` takes `now time.Time` rather than calling `time.Now()`.

## 4. `internal/expected` — small, but the API contract

Read `expected.go`, `expected_test.go`.

Concepts:
- Optional booleans as `*bool` (nil means "not stated"); the `Bool(p, def)` helper.
- `time.Parse` with `time.RFC3339`; `time.Duration` arithmetic; a capped value (`MaxClockSkew`) as policy
  expressed in code.
- The `jsonschema:"..."` struct tag: the go-sdk reads it to describe the field to an agent.

Exercises:
1. Add a `RequiredScopes []string` field and watch the MCP tool schemas pick it up (`TestToolList` prints
   nothing, so add a temporary `t.Log` of `tool.InputSchema` to see it).
2. Write a test that `Skew()` with `ClockSkewSeconds: 299` is 4m59s.
3. Explain why `NowOr` returns `(time.Time, error)` instead of panicking on a bad string.

## 5. `internal/saml` — the sharp edges

Read in this order: `ns.go`, `decode.go`, `paths.go`, `parse.go`, `sig.go`, `validate.go`, then the tests
(`decode_test.go`, `parse_test.go`, `validate_test.go`).

Concepts:
- Sentinel errors (`var ErrNotXML = errors.New(...)`) plus `fmt.Errorf("%w ...")` wrapping, checked with
  `errors.Is` in `TestDecodeErrors`. This is the Go error idiom you will be asked about.
- `compress/flate` with `io.LimitReader`: never trust the size of compressed input.
- `encoding/base64`: four alphabets, tried in order.
- etree: query by namespace URI, never prefix (`child`, `children`, `path`). `TestParseDialects` is why.
- A custom `MarshalJSON` on `Summary` so redaction cannot be forgotten; the `redactedSummary` alias type
  prevents infinite recursion (a classic Go trap: calling `json.Marshal(s)` inside `s.MarshalJSON`).
- The validator pattern: a struct holding per-run state, one method per check, nothing returns early.
  Compare with crewjam/saml's fail-fast style.
- External test package (`package saml_test`): needed because `internal/fixture` imports `saml`, so an
  internal test importing `fixture` would be an import cycle.
- Time comparisons with skew; why `!noa.After(now - skew)` and not `noa.Before(...)` (boundary is
  "on or after").

Exercises:
1. Add a `version` check that fails when `Response/@Version` is not `2.0`; it already lives in `checkStructure`,
   so move it into its own check with its own `Check` entry and update `expected.json` with
   `go test ./internal/diag -update`. Read the git diff before committing.
2. Write a table test for `diffNote` covering slash, case, scheme and environment.
3. Hand-write a fourth dialect XML (Shibboleth uses `saml2p:`/`saml2:` too but puts `xmlns` on
   `Response`) in `testdata/dialects/` and add it to `TestParseDialects`.

## 6. `internal/fixture` — the test IdP

Read `keys.go`, `idp.go`, `mutate.go`, `jwt.go`, `fixture_test.go`.

Concepts:
- Generics: `sortedKeys[V any](m map[string]V)` in `util.go` is the simplest possible generic function.
- `init()` functions registering into a package map (`register(Mutator{...})`): Go's plugin-registry idiom.
  Note the trade-off: order-independent, but you cannot see the full list in one place without
  `SAMLMutators()`.
- Closures capturing nothing but their arguments (`Apply func(doc, p)`), and mutators that change `Params`
  through the pointer (`p.Sign = "none"`).
- The goxmldsig gotcha documented on `attachSignature`: a library that mutates its input. Reproduce it by
  signing `el` directly instead of `el.Copy()` and watching `posture_comment_in_nameid` fail.
- Why `MintSAML` returns a `Minted` struct instead of three values: the caller needs the keys a mutator
  swapped in.

Exercises:
1. Write a mutator `audience_empty` that removes the `Audience` element entirely; add it to the catalog's
   `Mutator` field? No: one code can have several mutators, so leave the catalog alone and add the case to
   `samlCases()` in `internal/diag/golden_test.go`, then `-update`.
2. Write a JWT mutator `jwt_no_exp` that deletes `exp`; confirm `JWT_EXPIRED_OR_NOT_YET_VALID` fires.
3. Replace `idSuffix` with a `math/rand/v2` generator seeded from `RequestID` and explain what breaks in
   the golden files and why that is acceptable.

## 7. `internal/jwt`

Read `decode.go`, `jwks.go`, `validate.go`, `jwt_test.go`.

Concepts:
- golang-jwt's error model: `ErrTokenMalformed`, `ErrTokenSignatureInvalid` are sentinels you check with
  `errors.Is` even though the library wraps them (see `checkSignature`). golang-jwt joins claim errors with
  `errors.Join` when you let it validate claims; we turn that off (`WithoutClaimsValidation`) and check each
  claim ourselves so every failure gets its own evidence. Read `jwt/v5/errors.go` and `validator.go` to see
  the joined-error path you are not using, and be ready to explain `errors.Is` on a joined error.
- `crypto.PublicKey` is `any`; type assertions select RSA vs ECDSA (`keyDesc`).
- `net/http` with an injectable `*http.Client` and `context`: `fetchJWKS` is the only network call in the
  product, and `httptest.NewServer` in the tests stands in for the OP.
- `json.Number` vs `float64` when decoding numeric claims (`numericClaim`).

Exercises:
1. Write a test with `httptest` that returns a JWKS whose only key has `use: "enc"` and assert
   `JWT_KID_NOT_FOUND_IN_JWKS`.
2. Implement `at_hash` (left half of SHA-256 of the access token, base64url) behind the existing skip and
   add the fixture mutator.
3. Switch `Validate` to let golang-jwt validate claims, collect the joined error, and map each
   `errors.Is` branch to a finding. Compare the evidence quality with the hand-written version and
   decide which you would ship.

## 8. `internal/diag` — the pipeline and the golden harness

Read `sniff.go`, `pipeline.go`, `text.go`, `golden_test.go`.

Concepts:
- A `Kind` enum and a `switch` dispatcher; `regexp.MustCompile` at package init.
- `flag.Bool("update", ...)` in a test file: `go test ./internal/diag -update` regenerates `testdata/`.
  This is the golden-file idiom (crewjam and gotest.tools do the same).
- `go-cmp`'s `cmp.Diff` for readable test failures.
- Projecting a rich struct to a stable "golden" shape so volatile values (fresh cert fingerprints) do not
  churn the files.
- `os.ReadDir` over `testdata/` and the "no stray directories" test.

Exercises:
1. Add a `--symptom` to a golden case (it is carried, not interpreted) and confirm `-update` changes nothing.
2. Write a fuzz test `FuzzSniff` (`go test -fuzz=FuzzSniff -fuzztime=10s ./internal/diag`) seeded from
   the table in `sniff_test.go`; it must never panic.
3. Rank differently: demote `POSTURE_EMBEDDED_KEY_TRUST` below every fault even when faults are warnings.
   Which file changes, and how many `expected.json` files move?

## 9. `internal/mcpserver` — interfaces vs generics, for real

Read `server.go`, `tools.go`, `server_test.go`, and then the go-sdk source for `AddTool`
(`$(go env GOMODCACHE)/github.com/modelcontextprotocol/go-sdk@v1.8.0/mcp/server.go`, around `func AddTool`).

Concepts:
- `mcp.AddTool[In, Out any](s *Server, t *Tool, h ToolHandlerFor[In, Out])` is a generic function. The
  type parameters are inferred from the handler you pass (`s.samlDecode` has `In = samlDecodeIn`,
  `Out = samlDecodeOut`). The SDK reflects over `In` and `Out` to build JSON schemas and validates every
  call against them before your code runs. Compare with `Server.AddTool(t, h ToolHandler)`, the
  non-generic interface-based form that gives you raw JSON and no validation. Be able to say when you would
  pick each.
- Fields without `omitempty` are *required* in the inferred schema. That is why every optional input field
  has it, and why `cert_inspect.cert` does not.
- Method values as handlers (`s.samlDecode` captures `s`).
- `context.Context` as the first parameter of everything that might block or be cancelled; `Run` returns
  when the context is cancelled, which is how Ctrl-C stops the server.
- `mcp.NewInMemoryTransports()` for tests vs `CommandTransport` for the subprocess e2e test in
  `cmd/idpdoctor/mcp_e2e_test.go`.

Exercises:
1. Remove `omitempty` from `samlDecodeIn.Binding`, run `TestSAMLToolsEndToEnd`, read the validation error.
2. Add a `health` tool with `In = struct{}` and `Out = struct{ Version string }`; call it from the in-memory
   test.
3. Register one tool with the non-generic `s.mcp.AddTool` and unmarshal the arguments yourself; note what
   you lose.

## 10. `internal/oidc`, `internal/oauth`, `internal/bundle`, `internal/web` (v1 breadth)

Read `oidc/check.go`, `oauth/classify.go` + `oauth/pkce.go`, `bundle/bundle.go`, `web/server.go`.

Concepts:
- The same validator pattern as `saml`, applied to JSON (`map[string]any` with small typed accessors) and to
  URLs (`net/url`: query vs fragment parameters, `url.Values`).
- A table-driven classifier (`oauth/classify.go`): rules as data with a precedence order (vendor code, then
  description phrase, then bare error value). Compare with a chain of `if`s and decide which you would
  rather extend.
- `crypto/sha256` + `base64.RawURLEncoding` for PKCE S256 (RFC 7636 Appendix B is the test vector).
- `archive/zip` streaming with `CreateHeader`; why the bundle carries a hash of the artifact, not the artifact.
- `net/http` server hygiene: `http.MaxBytesReader`, `ReadHeaderTimeout`, `ErrorLog` to `io.Discard`, `Host`
  checks against DNS rebinding, `Shutdown` with a context. `net.ParseIP(host).IsLoopback()` is the whole
  "local only" rule.

Exercises:
1. Add `code_challenge_methods_supported` to the discovery checks: warn when `S256` is absent.
2. Add an Okta-shaped rule to `oauth/classify.go` (`E0000004` is an authentication failure) and a test.
3. Make `web.CheckAddr` accept a Unix socket path and explain why that is still "local only".

## 11. `internal/agent`: `os/exec`, pipes and context timeouts

Read `runner.go`, `envelope.go`, `explain.go`, `agenttest/agenttest.go`, then `runner_test.go`.

Concepts:
- `exec.CommandContext(ctx, bin, args...)`: when `ctx` is cancelled the child gets SIGKILL. `cmd.WaitDelay`
  is the subtle part: without it, `Wait` blocks until every pipe closes, and a grandchild (the MCP server
  the CLI spawned) that inherited stdout keeps the pipe open after the CLI died. Read the `os/exec` doc
  comment on `WaitDelay` and `Cancel`.
- `cmd.Env` is the whole environment, not a delta: `ScrubEnv` copies `os.Environ()` minus the banned keys.
  `exec.LookPath` happens at call time so a test can prepend a fake to `PATH` with `t.Setenv`.
- Stdin as `strings.NewReader(prompt)`, stdout/stderr into `bytes.Buffer`s. Why the prompt goes on stdin and
  not in `args` (process listings).
- `context.WithTimeout` only when the caller's context has no deadline (`ctx.Deadline()`), so an outer
  cancellation still wins.
- Error design: sentinels (`ErrTimeout`, `ErrDenied`) plus one typed error (`MalformedError`) carrying the
  head of stdout; `errors.Is` for the sentinel, `errors.As` for the payload. The envelope is returned
  alongside the error when it parsed, so usage can still be recorded.
- `encoding/json` on an evolving external schema: `json.RawMessage` for the parts you pass through
  (`structured_output`), ignored unknown fields for forward compatibility, `camelCase` vs `snake_case` tags
  because the CLI mixes both.

Exercises:
1. Remove `cmd.WaitDelay`, make the fake `claude` spawn `sleep 60 &` that inherits stdout, and watch
   `TestRunTimeout` hang. Put it back.
2. Add a `Retries int` to `Runner` that retries once on `ErrTimeout` only, and test it with a fake mode that
   sleeps on the first call and succeeds on the second (hint: a counter file in `FAKE_CLAUDE_RECORD`'s dir).
3. Replace the `bytes.Buffer` stdout with `cmd.StdoutPipe()` and a streaming JSON decoder; explain what you
   gain for `--output-format stream-json` and what you must now do about `Wait` ordering.

## 12. `encoding/json` v2 on Go 1.27 (no package to read; a probe)

This machine's Go 1.27 ships `encoding/json/v2` importable without a `GOEXPERIMENT`. `go.mod` says
`go 1.25.0`, so product code stays on v1; use v2 in a scratch module to learn where the semantics moved.
Measured here (write the probe yourself, it is 40 lines):

- A nil slice marshals as `[]` in v2 and `null` in v1. `finding.NewReport` initialises its slices precisely
  because v1 would otherwise emit `null` where the MCP output schema says array.
- v2 field matching is case-sensitive: `{"code":"X"}` does not fill a field tagged `json:"Code"`. v1 matches
  case-insensitively. Every struct that crosses a tool or model boundary in this repo has explicit lowercase
  tags for that reason.
- v2 rejects duplicate object keys (`jsontext: duplicate object member name`); v1 silently keeps the last. That
  is the JSON cousin of the SAML parser-differential class: two parsers, two answers.
- v2 refuses to marshal `time.Duration` without a `format` tag; v1 writes nanoseconds. v2 also does not
  coerce a JSON string into a `float64` field.
- `omitempty` on a zero `time.Time` omits nothing in either version; `omitzero` (v1 since 1.24, v2) does.

Exercises:
1. Write the probe module and reproduce each bullet; add one more difference you find in the v2 package doc
   ("Migrating to v2" section).
2. Port `internal/eval/report.go` to v2 in a scratch branch. Which `Ratio` workaround becomes unnecessary and
   which new option (`jsonv2.FormatNilSliceAsNull`, `jsontext.AllowDuplicateNames`, ...) would you need to keep
   byte-identical output?
3. Explain why `saml.Summary.MarshalJSON` (the redaction hook) keeps working under v2 and what the v2
   `json.MarshalerTo` interface would buy.

## 13. `embed` and `internal/eval`

Read `web/server.go` (the `//go:embed index.html` directive), `agent/agenttest/agenttest.go` (`//go:embed
fake-claude.sh` into a `[]byte`), then `eval/case.go`, `gen.go`, `run.go`, `judge.go`, `kappa.go`,
`report.go`, `eval_test.go`.

Concepts:
- `//go:embed` turns a file into a `string`, `[]byte` or `embed.FS` at compile time; the path is relative to
  the package directory and cannot reach `..`, which is why the fake script lives inside `agenttest/` and not
  in a shared `testdata/`. The binary is self-contained: `idpdoctor web` needs no files next to it.
- `math/rand/v2` with `rand.NewPCG(seed, stream)`: a stream per decision (`rng(label, i)`) so adding a class
  does not reshuffle another class's cases. Compare with one global generator consumed in order.
- A worker pool with a buffered channel as a semaphore, `sync.WaitGroup`, and one mutex around the tally and
  the shared counters; why the concurrency cap is 2 (subscription etiquette, not throughput).
- Content hashing for a cache key (`Case.Hash`): what is in it (artifact, expected, keys, symptom) and what is
  deliberately not (label, meta), so a relabel keeps cached model outputs.
- Cohen's kappa from a confusion matrix with a weight function; the quadratic weights make a one-step Likert
  disagreement cheap and a four-step one expensive. `NaN` as "undefined" and the `Ratio` type that renders it
  as `null`.
- Tests that use the fake `claude` for every arm, including the hard cap (`ErrMaxCalls`) and resume.

Exercises:
1. Embed `evals/rubric.md` into `internal/eval` as the default when `--rubric` is not given, keeping the file
   on disk as the editable source (hint: `embed.FS` + a `go:generate` copy, or move the file).
2. Add a `--shuffle` flag to `eval run` that randomises case order with a seed and show that cached results
   make the order irrelevant.
3. Write `TestKappaMatchesSklearn`: compute weighted kappa for a 5x5 matrix by hand (or from a published
   example) and assert to 1e-9.

## 14. Build tags and CI (no package to read)

The plan reserves `-tags e2e` for the Keycloak smoke test (v2). To practise now: create
`internal/diag/keycloak_e2e_test.go` with `//go:build e2e` on line 1 and a test that `t.Skip`s; confirm
`go test ./...` does not run it and `go test -tags e2e ./internal/diag -run Keycloak -v` does. Then read
`.github/workflows/ci.yml` and `Makefile`; both run the same four commands, and CI additionally fails if
`go generate` would change `docs/TAXONOMY.md`.

## Interview one-liners to be able to say

- "Errors are values: sentinels for identity, `%w` for cause, `errors.Is`/`errors.As` to unwrap, `errors.Join`
  when several things failed independently."
- "Interfaces describe behaviour at the call site; generics describe type relationships at the definition
  site. `AddTool` needs the concrete `In`/`Out` types to build schemas, so it is generic."
- "Table-driven tests put cases in data and logic in one place; golden files put expected output in files
  with an `-update` flag so a behaviour change is a reviewed diff."
- "`context.Context` carries cancellation and deadlines down the call stack; every blocking call takes
  one first."
- "Build tags select files at compile time; we use them to keep a slow Docker test and the one real
  `claude -p` call (`-tags live`) out of `go test ./...`."
- "`exec.CommandContext` kills the child on cancellation; `WaitDelay` is what stops a grandchild's inherited
  pipe from hanging `Wait`."
- "`//go:embed` makes the binary self-contained; the path cannot escape the package directory."
- "Cohen's kappa is agreement corrected for chance; weighted kappa makes near-misses on an ordinal scale
  cheaper than far misses."
