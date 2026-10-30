package severity

import (
	"math"
	"strings"
)

// scoreV2 computes a CVSS v2 base score from a base vector exactly as NVD
// stores one ("AV:N/AC:L/Au:N/C:P/I:P/A:P": the six base metrics, in the
// specification's order, nothing before or after) and bands it on NVD's own
// v2 table (D156). v2 has no Critical band, and its Low starts at 0.0.
//
// The formula and weights are the CVSS v2 specification's (section 3.2.1):
//
//	Impact         = 10.41 * (1 - (1-C) * (1-I) * (1-A))
//	Exploitability = 20 * AV * AC * Au
//	f(Impact)      = 0 if Impact == 0, else 1.176
//	BaseScore      = round1(((0.6*Impact) + (0.4*Exploitability) - 1.5) * f(Impact))
//
// Anything else -- temporal or environmental metrics appended, another order,
// lower-case letters, a prefix -- is refused rather than read loosely: an
// unscorable vector stays Unknown (D17), and a guessed one would be a band
// nobody published.
func scoreV2(vector string) (float64, Band, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) != len(v2Metrics) {
		return 0, Unknown, false
	}
	w := make([]float64, len(v2Metrics))
	for i, m := range v2Metrics {
		name, val, ok := strings.Cut(parts[i], ":")
		if !ok || name != m.name {
			return 0, Unknown, false
		}
		weight, ok := m.values[val]
		if !ok {
			return 0, Unknown, false
		}
		w[i] = weight
	}
	av, ac, au, c, in, a := w[0], w[1], w[2], w[3], w[4], w[5]
	impact := 10.41 * (1 - (1-c)*(1-in)*(1-a))
	exploitability := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	score := math.Round(((0.6*impact)+(0.4*exploitability)-1.5)*f*10) / 10
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 7.0:
		return score, High, true
	case score >= 4.0:
		// No v2 vector scores 3.9 (all 729 base vectors computed), so this
		// edge is held from above only: moving it to 3.9 changes no answer.
		return score, Medium, true
	default:
		return score, Low, true
	}
}

var v2Metrics = []struct {
	name   string
	values map[string]float64
}{
	{"AV", map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}},
	{"AC", map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}},
	{"Au", map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}},
	{"C", map[string]float64{"N": 0, "P": 0.275, "C": 0.660}},
	{"I", map[string]float64{"N": 0, "P": 0.275, "C": 0.660}},
	{"A", map[string]float64{"N": 0, "P": 0.275, "C": 0.660}},
}
