package severity

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// CVSS v4.0 base score.
//
// v4 is not a formula. Scoring derives a six-digit macrovector from the
// metrics via the EQ1-EQ6 equivalence classes, looks that macrovector up in a
// 270-entry table, and then interpolates: for each equivalence class, how far
// this vector sits below the most severe vector in its own macrovector, as a
// proportion of that macrovector's depth, scaled by the scoring gap to the
// next lower macrovector. The mean of those is subtracted from the table
// value.
//
// This is a line-by-line transliteration of FIRST's reference implementation
// (cvss_score.js, macroVector(), max_composed.js, max_severity.js), which is
// the authority — the prose specification does not determine the answer on
// its own. It is meant to stay recognisable against that source, for the same
// reason as the apk comparer (D9): the tidier rewrite is where a quiet
// scoring bug gets in, and a wrong band is a build that passes when it should
// have failed.
//
// Reference: https://github.com/FIRSTdotorg/cvss-v4-calculator
// Copyright FIRST, Red Hat, and contributors. SPDX-License-Identifier: BSD-2-Clause

//go:embed testdata/cvss_lookup.json
var cvssLookupJSON []byte

// cvssLookup is the macrovector table: 270 entries, one score each. It is
// data, not a formula — there is nothing to derive it from — so it is
// vendored rather than fetched. A scanner that reaches the network to decide
// a severity is not one that runs offline (D14).
var cvssLookup = func() map[string]float64 {
	var m map[string]float64
	if err := json.Unmarshal(cvssLookupJSON, &m); err != nil {
		panic("severity: embedded CVSS v4 lookup table is unreadable: " + err.Error())
	}
	if len(m) != 270 {
		panic(fmt.Sprintf("severity: CVSS v4 lookup table has %d entries, want 270", len(m)))
	}
	return m
}()

// Metric level indices. These are ordering positions used to measure severity
// distance within a macrovector, not weights — the arithmetic only ever takes
// differences between two of them, both read from the same table.
//
// That is why SC starts at 0.1 rather than 0.0, matching the reference: the
// offset cancels. Shifting a whole table by a constant is therefore invisible
// (verified as a mutation), while reordering or collapsing one is not.
var (
	v4AVLevels = map[string]float64{"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
	v4PRLevels = map[string]float64{"N": 0.0, "L": 0.1, "H": 0.2}
	v4UILevels = map[string]float64{"N": 0.0, "P": 0.1, "A": 0.2}
	v4ACLevels = map[string]float64{"L": 0.0, "H": 0.1}
	v4ATLevels = map[string]float64{"N": 0.0, "P": 0.1}
	v4VCLevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4VILevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4VALevels = map[string]float64{"H": 0.0, "L": 0.1, "N": 0.2}
	v4SCLevels = map[string]float64{"H": 0.1, "L": 0.2, "N": 0.3}
	v4SILevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	v4SALevels = map[string]float64{"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
	v4CRLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
	v4IRLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
	v4ARLevels = map[string]float64{"H": 0.0, "M": 0.1, "L": 0.2}
)

// maxComposed: the highest-severity vector fragments for each equivalence
// class level, from max_composed.js. Composed across the classes, they give
// the candidate "most severe vector in this macrovector".
var (
	v4MaxEQ1 = [][]string{
		{"AV:N/PR:N/UI:N/"},
		{"AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"},
		{"AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"},
	}
	v4MaxEQ2 = [][]string{
		{"AC:L/AT:N/"},
		{"AC:H/AT:N/", "AC:L/AT:P/"},
	}
	// Indexed [eq3][eq6]. eq3=2 exists only with eq6=1.
	v4MaxEQ3EQ6 = [3]map[int][]string{
		{
			0: {"VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"},
			1: {"VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"},
		},
		{
			0: {"VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"},
			1: {
				"VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
				"VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
				"VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
			},
		},
		{
			1: {"VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"},
		},
	}
	v4MaxEQ4 = [][]string{
		{"SC:H/SI:S/SA:S/"},
		{"SC:H/SI:H/SA:H/"},
		{"SC:L/SI:L/SA:L/"},
	}
	v4MaxEQ5 = [][]string{{"E:A/"}, {"E:P/"}, {"E:U/"}}
)

// maxSeverity: the depth of each macrovector, used as the denominator of the
// proportional distance. From max_severity.js; "+1" is already baked in there.
var (
	v4MaxSeverityEQ1    = [3]float64{1, 4, 5}
	v4MaxSeverityEQ2    = [2]float64{1, 2}
	v4MaxSeverityEQ3EQ6 = [3]map[int]float64{
		{0: 7, 1: 6},
		{0: 8, 1: 8},
		{1: 10},
	}
	v4MaxSeverityEQ4 = [3]float64{6, 5, 4}
)

// v4Metrics is a parsed vector. Every metric the scorer reads goes through m,
// which applies the defaults and the modified-metric overrides.
type v4Metrics map[string]string

// m resolves one metric the way the reference does.
//
// Absent metrics default to their worst case, not to a neutral one: E:X means
// E:A, and CR/IR/AR:X mean H. Almost every stored vector is base-only, so
// this path decides the score for nearly all real data — defaulting the other
// way would systematically under-score the entire database.
func (v v4Metrics) m(metric string) string {
	selected, ok := v[metric]
	if !ok {
		selected = "X"
	}
	switch {
	case metric == "E" && selected == "X":
		return "A"
	case metric == "CR" && selected == "X":
		return "H"
	case metric == "IR" && selected == "X":
		return "H"
	case metric == "AR" && selected == "X":
		return "H"
	}
	// Environmental metrics overwrite their base counterparts when present
	// and not X.
	if modified, ok := v["M"+metric]; ok && modified != "X" {
		return modified
	}
	return selected
}

// v4Required are the base metrics a vector must carry to be scorable.
//
// Checking presence separately from value is redundant — a missing metric
// resolves to "X", which no level table defines, so the value check below
// rejects it too. It is kept for the error message: "has no SA" says what to
// fix, "SA:X is not a defined value" makes the reader work it out.
var v4Required = []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"}

func scoreV4(vector string) (float64, error) {
	parsed, err := parseVector(vector, "CVSS:4.0")
	if err != nil {
		return 0, err
	}
	metrics := v4Metrics(parsed)
	for _, key := range v4Required {
		if _, ok := parsed[key]; !ok {
			return 0, fmt.Errorf("%w: %q has no %s", ErrUnscorable, vector, key)
		}
	}

	// Every metric that participates must have a defined value. The
	// reference does no validation and produces NaN for a bad one, which
	// would surface as a plausible-looking band rather than an error.
	for key, table := range map[string]map[string]float64{
		"AV": v4AVLevels, "PR": v4PRLevels, "UI": v4UILevels,
		"AC": v4ACLevels, "AT": v4ATLevels,
		"VC": v4VCLevels, "VI": v4VILevels, "VA": v4VALevels,
		"SC": v4SCLevels, "SI": v4SILevels, "SA": v4SALevels,
		"CR": v4CRLevels, "IR": v4IRLevels, "AR": v4ARLevels,
	} {
		if _, ok := table[metrics.m(key)]; !ok {
			return 0, fmt.Errorf("%w: %s:%s in %q is not a defined value",
				ErrUnscorable, key, metrics.m(key), vector)
		}
	}
	if e := metrics.m("E"); e != "A" && e != "P" && e != "U" {
		return 0, fmt.Errorf("%w: E:%s in %q is not a defined value", ErrUnscorable, e, vector)
	}

	// Exception for no impact on system (shortcut).
	noImpact := true
	for _, key := range []string{"VC", "VI", "VA", "SC", "SI", "SA"} {
		if metrics.m(key) != "N" {
			noImpact = false
			break
		}
	}
	if noImpact {
		return 0.0, nil
	}

	mv, err := macroVector(metrics)
	if err != nil {
		return 0, fmt.Errorf("%w: %v in %q", ErrUnscorable, err, vector)
	}
	value, ok := cvssLookup[mv]
	if !ok {
		return 0, fmt.Errorf("%w: macrovector %s from %q is not in the table",
			ErrUnscorable, mv, vector)
	}

	eq1 := int(mv[0] - '0')
	eq2 := int(mv[1] - '0')
	eq3 := int(mv[2] - '0')
	eq4 := int(mv[3] - '0')
	eq5 := int(mv[4] - '0')
	eq6 := int(mv[5] - '0')

	// 1a. The maximal scoring difference: the gap to the next lower
	// macrovector in each equivalence class. Where no lower macrovector
	// exists the class is dropped from the mean rather than counted as zero
	// — the reference does this with NaN, which is what `ok` stands in for.
	digits := func(a, b, c, d, e, f int) string {
		return fmt.Sprintf("%d%d%d%d%d%d", a, b, c, d, e, f)
	}
	scoreEQ1Lower, okEQ1 := cvssLookup[digits(eq1+1, eq2, eq3, eq4, eq5, eq6)]
	scoreEQ2Lower, okEQ2 := cvssLookup[digits(eq1, eq2+1, eq3, eq4, eq5, eq6)]

	// eq3 and eq6 move together.
	var scoreEQ3EQ6Lower float64
	var okEQ3EQ6 bool
	switch {
	case eq3 == 1 && eq6 == 1: // 11 --> 21
		scoreEQ3EQ6Lower, okEQ3EQ6 = cvssLookup[digits(eq1, eq2, eq3+1, eq4, eq5, eq6)]
	case eq3 == 0 && eq6 == 1: // 01 --> 11
		scoreEQ3EQ6Lower, okEQ3EQ6 = cvssLookup[digits(eq1, eq2, eq3+1, eq4, eq5, eq6)]
	case eq3 == 1 && eq6 == 0: // 10 --> 11
		scoreEQ3EQ6Lower, okEQ3EQ6 = cvssLookup[digits(eq1, eq2, eq3, eq4, eq5, eq6+1)]
	case eq3 == 0 && eq6 == 0: // 00 --> 01 or 00 --> 10, take the higher
		left, okLeft := cvssLookup[digits(eq1, eq2, eq3, eq4, eq5, eq6+1)]
		right, okRight := cvssLookup[digits(eq1, eq2, eq3+1, eq4, eq5, eq6)]
		// The reference compares with NaN semantics: a missing left never
		// wins, so the right branch is the fallback either way.
		if okLeft && okRight && left > right {
			scoreEQ3EQ6Lower, okEQ3EQ6 = left, true
		} else {
			scoreEQ3EQ6Lower, okEQ3EQ6 = right, okRight
		}
	default: // 21 --> 32, which does not exist
		scoreEQ3EQ6Lower, okEQ3EQ6 = cvssLookup[digits(eq1, eq2, eq3+1, eq4, eq5, eq6+1)]
	}

	scoreEQ4Lower, okEQ4 := cvssLookup[digits(eq1, eq2, eq3, eq4+1, eq5, eq6)]
	scoreEQ5Lower, okEQ5 := cvssLookup[digits(eq1, eq2, eq3, eq4, eq5+1, eq6)]

	// 1b. The severity distance from a highest-severity vector in the same
	// macrovector. Compose the candidates and take the first that is not more
	// severe than the vector being scored in any metric.
	eq3eq6Maxes, ok := v4MaxEQ3EQ6[eq3][eq6]
	if !ok {
		return 0, fmt.Errorf("%w: macrovector %s from %q has no composed maximum",
			ErrUnscorable, mv, vector)
	}

	var (
		dAV, dPR, dUI, dAC, dAT      float64
		dVC, dVI, dVA, dSC, dSI, dSA float64
		dCR, dIR, dAR                float64
		found                        bool
	)
compose:
	for _, max1 := range v4MaxEQ1[eq1] {
		for _, max2 := range v4MaxEQ2[eq2] {
			for _, max36 := range eq3eq6Maxes {
				for _, max4 := range v4MaxEQ4[eq4] {
					for _, max5 := range v4MaxEQ5[eq5] {
						maxVector := parseMaxVector(max1 + max2 + max36 + max4 + max5)

						dAV = v4AVLevels[metrics.m("AV")] - v4AVLevels[maxVector["AV"]]
						dPR = v4PRLevels[metrics.m("PR")] - v4PRLevels[maxVector["PR"]]
						dUI = v4UILevels[metrics.m("UI")] - v4UILevels[maxVector["UI"]]
						dAC = v4ACLevels[metrics.m("AC")] - v4ACLevels[maxVector["AC"]]
						dAT = v4ATLevels[metrics.m("AT")] - v4ATLevels[maxVector["AT"]]
						dVC = v4VCLevels[metrics.m("VC")] - v4VCLevels[maxVector["VC"]]
						dVI = v4VILevels[metrics.m("VI")] - v4VILevels[maxVector["VI"]]
						dVA = v4VALevels[metrics.m("VA")] - v4VALevels[maxVector["VA"]]
						dSC = v4SCLevels[metrics.m("SC")] - v4SCLevels[maxVector["SC"]]
						dSI = v4SILevels[metrics.m("SI")] - v4SILevels[maxVector["SI"]]
						dSA = v4SALevels[metrics.m("SA")] - v4SALevels[maxVector["SA"]]
						dCR = v4CRLevels[metrics.m("CR")] - v4CRLevels[maxVector["CR"]]
						dIR = v4IRLevels[metrics.m("IR")] - v4IRLevels[maxVector["IR"]]
						dAR = v4ARLevels[metrics.m("AR")] - v4ARLevels[maxVector["AR"]]

						negative := false
						for _, d := range []float64{dAV, dPR, dUI, dAC, dAT,
							dVC, dVI, dVA, dSC, dSI, dSA, dCR, dIR, dAR} {
							if d < 0 {
								negative = true
								break
							}
						}
						if negative {
							continue
						}
						// Any one of the maxima that reaches it is enough.
						found = true
						break compose
					}
				}
			}
		}
	}
	if !found {
		// The reference falls through here using the last candidate's
		// distances, which is silently wrong rather than loudly. Every
		// macrovector in the table has a reachable maximum, so arriving here
		// means the composition tables and the lookup table disagree.
		return 0, fmt.Errorf("%w: no composed maximum in macrovector %s reaches %q",
			ErrUnscorable, mv, vector)
	}

	currentEQ1 := dAV + dPR + dUI
	currentEQ2 := dAC + dAT
	currentEQ3EQ6 := dVC + dVI + dVA + dCR + dIR + dAR
	currentEQ4 := dSC + dSI + dSA
	const currentEQ5 = 0.0

	const step = 0.1
	// Multiply by step because the distances above are in level units.
	maxSeverityEQ1 := v4MaxSeverityEQ1[eq1] * step
	maxSeverityEQ2 := v4MaxSeverityEQ2[eq2] * step
	maxSeverityEQ3EQ6 := v4MaxSeverityEQ3EQ6[eq3][eq6] * step
	maxSeverityEQ4 := v4MaxSeverityEQ4[eq4] * step

	// 1c/1d. The proportion of the distance, times the maximal scoring
	// difference.
	var normalized [5]float64
	existingLower := 0
	if okEQ1 {
		existingLower++
		normalized[0] = (value - scoreEQ1Lower) * (currentEQ1 / maxSeverityEQ1)
	}
	if okEQ2 {
		existingLower++
		normalized[1] = (value - scoreEQ2Lower) * (currentEQ2 / maxSeverityEQ2)
	}
	if okEQ3EQ6 {
		existingLower++
		normalized[2] = (value - scoreEQ3EQ6Lower) * (currentEQ3EQ6 / maxSeverityEQ3EQ6)
	}
	if okEQ4 {
		existingLower++
		normalized[3] = (value - scoreEQ4Lower) * (currentEQ4 / maxSeverityEQ4)
	}
	if okEQ5 {
		// For eq5 the percentage is always 0.
		existingLower++
		normalized[4] = (value - scoreEQ5Lower) * currentEQ5
	}

	// 2. The mean of those proportional distances.
	meanDistance := 0.0
	if existingLower > 0 {
		meanDistance = (normalized[0] + normalized[1] + normalized[2] +
			normalized[3] + normalized[4]) / float64(existingLower)
	}

	// 3. The macrovector's score minus that mean, clamped, to one decimal.
	//
	// Neither clamp is reachable by any of the 3004 corpus vectors: every
	// severity distance is non-negative by the selection above, so the mean
	// can only subtract. They are the reference's, carried over rather than
	// dropped — this is a transliteration, and a guard removed because today's
	// data does not reach it is a guard removed.
	value -= meanDistance
	if value < 0 {
		value = 0.0
	}
	if value > 10 {
		value = 10.0
	}
	// math.Round, not roundup: v4's reference rounds to nearest here, and it
	// is the authority. Using v3's roundup would shift a swathe of scores up
	// by a tenth, which lands some of them in the next band.
	return math.Round(value*10) / 10, nil
}

// parseMaxVector splits a composed maximum like "AV:N/PR:N/UI:N/AC:L/..." into
// its metrics.
//
// The reference reads each metric out with indexOf, which would find a metric
// name occurring as a substring of an earlier one. No collision exists among
// the names these fragments carry, so this is equivalent and does not have to
// be reasoned about again.
func parseMaxVector(s string) map[string]string {
	out := make(map[string]string, 15)
	for _, part := range strings.Split(s, "/") {
		if part == "" {
			continue
		}
		if key, value, ok := strings.Cut(part, ":"); ok {
			out[key] = value
		}
	}
	return out
}

// macroVector derives the six equivalence-class digits, from macroVector() in
// cvss_score.js.
func macroVector(v v4Metrics) (string, error) {
	// EQ1: 0-AV:N and PR:N and UI:N
	//      1-(AV:N or PR:N or UI:N) and not (AV:N and PR:N and UI:N) and not AV:P
	//      2-AV:P or not(AV:N or PR:N or UI:N)
	var eq1 int
	switch {
	case v.m("AV") == "N" && v.m("PR") == "N" && v.m("UI") == "N":
		eq1 = 0
	case (v.m("AV") == "N" || v.m("PR") == "N" || v.m("UI") == "N") &&
		!(v.m("AV") == "N" && v.m("PR") == "N" && v.m("UI") == "N") &&
		v.m("AV") != "P":
		eq1 = 1
	case v.m("AV") == "P" ||
		!(v.m("AV") == "N" || v.m("PR") == "N" || v.m("UI") == "N"):
		eq1 = 2
	default:
		return "", fmt.Errorf("no EQ1 class")
	}

	// EQ2: 0-(AC:L and AT:N)  1-not(AC:L and AT:N)
	eq2 := 1
	if v.m("AC") == "L" && v.m("AT") == "N" {
		eq2 = 0
	}

	// EQ3: 0-(VC:H and VI:H)
	//      1-not(VC:H and VI:H) and (VC:H or VI:H or VA:H)
	//      2-not (VC:H or VI:H or VA:H)
	var eq3 int
	switch {
	case v.m("VC") == "H" && v.m("VI") == "H":
		eq3 = 0
	case v.m("VC") == "H" || v.m("VI") == "H" || v.m("VA") == "H":
		eq3 = 1
	default:
		eq3 = 2
	}

	// EQ4: 0-(MSI:S or MSA:S)
	//      1-not (MSI:S or MSA:S) and (SC:H or SI:H or SA:H)
	//      2-neither
	//
	// Safety is a MODIFIED subsequent metric: EQ4=0 is reachable only through
	// MSI:S / MSA:S, never through a base SI / SA.
	//
	// Reading m("SI") here instead would behave identically on every valid
	// vector, because m already resolves MSI over SI — the two only diverge on
	// a base SI:S, which CVSS does not define and no live record carries. The
	// reference reads MSI, so this does.
	var eq4 int
	switch {
	case v.m("MSI") == "S" || v.m("MSA") == "S":
		eq4 = 0
	case v.m("SC") == "H" || v.m("SI") == "H" || v.m("SA") == "H":
		eq4 = 1
	default:
		eq4 = 2
	}

	// EQ5: 0-E:A  1-E:P  2-E:U
	var eq5 int
	switch v.m("E") {
	case "A":
		eq5 = 0
	case "P":
		eq5 = 1
	case "U":
		eq5 = 2
	default:
		return "", fmt.Errorf("no EQ5 class for E:%s", v.m("E"))
	}

	// EQ6: 0-(CR:H and VC:H) or (IR:H and VI:H) or (AR:H and VA:H)  1-not
	eq6 := 1
	if (v.m("CR") == "H" && v.m("VC") == "H") ||
		(v.m("IR") == "H" && v.m("VI") == "H") ||
		(v.m("AR") == "H" && v.m("VA") == "H") {
		eq6 = 0
	}

	return fmt.Sprintf("%d%d%d%d%d%d", eq1, eq2, eq3, eq4, eq5, eq6), nil
}
