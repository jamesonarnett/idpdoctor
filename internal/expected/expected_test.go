// SPDX-License-Identifier: Apache-2.0

package expected

import (
	"errors"
	"testing"
	"time"
)

func TestNowOr(t *testing.T) {
	fallback := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got, _ := (Expected{}).NowOr(fallback); !got.Equal(fallback) {
		t.Error("empty now must fall back")
	}
	if got, err := (Expected{Now: "2026-01-15T12:00:00Z"}).NowOr(fallback); err != nil || got.Year() != 2026 || got.Day() != 15 {
		t.Errorf("got %v %v", got, err)
	}
	if _, err := (Expected{Now: "yesterday"}).NowOr(fallback); !errors.Is(err, ErrBadNow) {
		t.Errorf("err = %v", err)
	}
}

func TestSkewCapped(t *testing.T) {
	tests := []struct {
		in   int
		want time.Duration
	}{{0, DefaultClockSkew}, {-5, DefaultClockSkew}, {60, time.Minute}, {3600, MaxClockSkew}}
	for _, tc := range tests {
		if got := (Expected{ClockSkewSeconds: tc.in}).Skew(); got != tc.want {
			t.Errorf("skew(%d) = %v want %v", tc.in, got, tc.want)
		}
	}
}
