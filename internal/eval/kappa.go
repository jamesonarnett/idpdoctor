// SPDX-License-Identifier: Apache-2.0

package eval

import "math"

// Kappa is Cohen's kappa for two raters over categorical labels. Values:
// 1 perfect, 0 chance, negative worse than chance. NaN when both raters
// used one category throughout (no chance to disagree). a and b are
// paired ratings; cats is the ordered category list.
func Kappa(a, b []int, cats []int) float64 {
	n := len(a)
	if n == 0 || n != len(b) {
		return math.NaN()
	}
	idx := map[int]int{}
	for i, c := range cats {
		idx[c] = i
	}
	k := len(cats)
	obs := make([][]float64, k)
	for i := range obs {
		obs[i] = make([]float64, k)
	}
	for i := range a {
		obs[idx[a[i]]][idx[b[i]]]++
	}
	return kappaFromMatrix(obs, func(i, j int) float64 {
		if i == j {
			return 0
		}
		return 1
	})
}

// WeightedKappa is Cohen's kappa with quadratic weights, for ordinal
// scores such as a 1-5 Likert fix score: a disagreement of one step costs
// less than one of four steps.
func WeightedKappa(a, b []int, cats []int) float64 {
	n := len(a)
	if n == 0 || n != len(b) {
		return math.NaN()
	}
	idx := map[int]int{}
	for i, c := range cats {
		idx[c] = i
	}
	k := len(cats)
	obs := make([][]float64, k)
	for i := range obs {
		obs[i] = make([]float64, k)
	}
	for i := range a {
		obs[idx[a[i]]][idx[b[i]]]++
	}
	denom := float64((k - 1) * (k - 1))
	return kappaFromMatrix(obs, func(i, j int) float64 {
		d := float64(i - j)
		return d * d / denom
	})
}

// kappaFromMatrix computes 1 - sum(w*obs) / sum(w*exp) over the confusion
// matrix with disagreement weights w (0 on the diagonal).
func kappaFromMatrix(obs [][]float64, w func(i, j int) float64) float64 {
	k := len(obs)
	var n float64
	row := make([]float64, k)
	col := make([]float64, k)
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			n += obs[i][j]
			row[i] += obs[i][j]
			col[j] += obs[i][j]
		}
	}
	var wo, we float64
	for i := 0; i < k; i++ {
		for j := 0; j < k; j++ {
			wo += w(i, j) * obs[i][j] / n
			we += w(i, j) * row[i] * col[j] / (n * n)
		}
	}
	if we == 0 {
		return math.NaN()
	}
	return 1 - wo/we
}

// PercentAgreement is the share of pairs that agree exactly.
func PercentAgreement(a, b []int) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return math.NaN()
	}
	agree := 0
	for i := range a {
		if a[i] == b[i] {
			agree++
		}
	}
	return float64(agree) / float64(len(a))
}
