// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// bannedFixPhrases are security regressions a fix template must never
// recommend (BUILD_PLAN 2.7). Matching is case-insensitive substring.
var bannedFixPhrases = []string{
	"disable signature",
	"turn off signature",
	"skip signature",
	"accept unsigned",
	"allow unsigned",
	"increase clock skew",
	"raise clock skew",
	"widen the window",
	"accept expired",
	"allow alg none",
}

func TestCatalogShape(t *testing.T) {
	seen := map[Code]bool{}
	faults, postures := 0, 0
	for _, s := range Catalog {
		if seen[s.Code] {
			t.Errorf("duplicate code %s", s.Code)
		}
		seen[s.Code] = true

		switch s.Lane {
		case LaneFault:
			faults++
			if s.Number == 0 {
				t.Errorf("%s: fault classes need a taxonomy number", s.Code)
			}
		case LanePosture:
			postures++
			if !strings.HasPrefix(string(s.Code), "POSTURE_") {
				t.Errorf("%s: posture codes must be prefixed POSTURE_", s.Code)
			}
		default:
			t.Errorf("%s: unknown lane %q", s.Code, s.Lane)
		}
		if n := utf8.RuneCountInString(s.Title); n == 0 || n > 80 {
			t.Errorf("%s: title must be 1..80 chars, got %d", s.Code, n)
		}
		if s.Fix == "" || s.Signal == "" || s.Protocol == "" || s.Tier == "" || s.Kind == "" {
			t.Errorf("%s: Fix, Signal, Protocol, Tier and Kind are required", s.Code)
		}
		if len(s.MergedFrom) == 0 {
			t.Errorf("%s: MergedFrom provenance is required (R1)", s.Code)
		}
		lower := strings.ToLower(s.Fix)
		for _, p := range bannedFixPhrases {
			if strings.Contains(lower, p) {
				t.Errorf("%s: fix recommends a security regression: %q", s.Code, p)
			}
		}
	}
	if faults != 25 {
		t.Errorf("want 25 failure classes, got %d", faults)
	}
	if postures != 8 {
		t.Errorf("want 8 posture codes, got %d", postures)
	}
}

func TestTaxonomyNumbersAreSequential(t *testing.T) {
	want := 1
	for _, s := range Catalog {
		if s.Lane != LaneFault {
			continue
		}
		if s.Number != want {
			t.Errorf("%s: number %d, want %d (catalog must stay in taxonomy order)", s.Code, s.Number, want)
		}
		want++
	}
}

// TestTaxonomyDocInSync fails when docs/TAXONOMY.md was not regenerated after
// a codes.go edit. Run `go generate ./...` to fix.
func TestTaxonomyDocInSync(t *testing.T) {
	got, err := os.ReadFile("../../docs/TAXONOMY.md")
	if err != nil {
		t.Fatalf("read TAXONOMY.md: %v (run go generate ./...)", err)
	}
	if string(got) != RenderTaxonomy() {
		t.Fatal("docs/TAXONOMY.md is stale; run `go generate ./...`")
	}
}

func TestNewFillsFromCatalog(t *testing.T) {
	f := New(SAMLAudienceMismatch, Evidence{Path: "/Response/Assertion/Conditions/AudienceRestriction/Audience", Actual: "a", Expected: "b"})
	if f.Lane != LaneFault || f.Severity != SeverityError || f.Title == "" || f.Fix == "" {
		t.Errorf("New did not fill from catalog: %+v", f)
	}
	if f.Confidence != 1.0 || f.Source != "validator" {
		t.Errorf("defaults wrong: %+v", f)
	}
	if New(PostureWeakAlgorithm).Evidence == nil {
		t.Error("Evidence must be non-nil so JSON renders []")
	}
}

func TestNewPanicsOnUnknownCode(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for unknown code")
		}
	}()
	New(Code("NOPE"))
}

func TestSortOrder(t *testing.T) {
	fs := []Finding{
		New(PostureWeakAlgorithm),
		{Code: SAMLIssuerMismatch, Lane: LaneFault, Severity: SeverityWarn, Confidence: 1},
		{Code: SAMLTimeWindowInvalid, Lane: LaneFault, Severity: SeverityError, Confidence: 0.7},
		{Code: SAMLAudienceMismatch, Lane: LaneFault, Severity: SeverityError, Confidence: 1},
		{Code: SAMLSignatureInvalid, Lane: LaneFault, Severity: SeverityError, Confidence: 1},
	}
	Sort(fs)
	want := []Code{SAMLAudienceMismatch, SAMLSignatureInvalid, SAMLTimeWindowInvalid, SAMLIssuerMismatch, PostureWeakAlgorithm}
	for i, w := range want {
		if fs[i].Code != w {
			t.Errorf("position %d: got %s want %s", i, fs[i].Code, w)
		}
	}
}

func TestReportNeedsDedup(t *testing.T) {
	r := NewReport("saml_response")
	r.AddCheck(Check{Name: "audience", Status: CheckSkip, Needs: "sp_entity_id"})
	r.AddCheck(Check{Name: "issuer", Status: CheckSkip, Needs: "sp_entity_id"})
	r.AddCheck(Check{Name: "status", Status: CheckPass})
	if len(r.Needs) != 1 || r.Needs[0] != "sp_entity_id" {
		t.Errorf("needs = %v", r.Needs)
	}
	if !r.OK() {
		t.Error("report with no error findings should be OK")
	}
	r.Add(New(SAMLStatusNotSuccess))
	if r.OK() {
		t.Error("report with an error finding should not be OK")
	}
}
