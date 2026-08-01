package severity

import (
	"fmt"
	"math"
	"strings"
)

// CVSS v3.1 base score, from the specification's §7.1 formula. v3.0 vectors
// are scored by the same code: the base equations are identical between the
// two, and 3.1 changed only the rounding definition and the prose. The live
// database holds both prefixes (925 at 3.1, 256 at 3.0).
//
// This is a transliteration and is meant to stay one. The same reasoning as
// the apk comparer (D9) applies: a tidier rewrite is how a quiet scoring bug
// gets in, and a wrong band here is a build that passes when it should fail.

// Metric weights, verbatim from the specification's tables.
var (
	v3AttackVector = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	v3AttackComp   = map[string]float64{"L": 0.77, "H": 0.44}
	v3UserInteract = map[string]float64{"N": 0.85, "R": 0.62}
	v3CIA          = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	v3Scope        = map[string]bool{"U": false, "C": true}

	// The one metric whose weight depends on another metric. PR:L and PR:H
	// are worth more when the scope has changed, because escaping a
	// security authority is worth more than acting within it. Collapsing
	// these two tables into one under-scores every scope-changed vector
	// that requires privileges — silently, and downward.
	v3PrivRequiredUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	v3PrivRequiredChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

func scoreV3(vector string) (float64, error) {
	metrics, err := parseVector(vector, "CVSS:3.0", "CVSS:3.1")
	if err != nil {
		return 0, err
	}

	scopeCode, err := lookupCode(metrics, "S", v3Scope, vector)
	if err != nil {
		return 0, err
	}
	scopeChanged := v3Scope[scopeCode]

	privTable := v3PrivRequiredUnchanged
	if scopeChanged {
		privTable = v3PrivRequiredChanged
	}

	av, err := lookup(metrics, "AV", v3AttackVector, vector)
	if err != nil {
		return 0, err
	}
	ac, err := lookup(metrics, "AC", v3AttackComp, vector)
	if err != nil {
		return 0, err
	}
	pr, err := lookup(metrics, "PR", privTable, vector)
	if err != nil {
		return 0, err
	}
	ui, err := lookup(metrics, "UI", v3UserInteract, vector)
	if err != nil {
		return 0, err
	}
	c, err := lookup(metrics, "C", v3CIA, vector)
	if err != nil {
		return 0, err
	}
	i, err := lookup(metrics, "I", v3CIA, vector)
	if err != nil {
		return 0, err
	}
	a, err := lookup(metrics, "A", v3CIA, vector)
	if err != nil {
		return 0, err
	}

	iscBase := 1 - ((1 - c) * (1 - i) * (1 - a))

	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0, nil
	}
	if scopeChanged {
		return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundup(math.Min(impact+exploitability, 10)), nil
}

// roundup is the specification's own, given in v3.1 §Appendix A: the smallest
// number to one decimal place that is not less than the input.
//
// The spec states it in integer arithmetic rather than as ceil(x*10)/10
// precisely because floating point makes the naive version disagree: a value
// that is mathematically 8.9 can be held as 8.900000000000001, which ceil
// lifts to 9.0 — moving a High finding to Critical. The scaling to 100000
// and the 10000 remainder test absorb exactly that representation error.
func roundup(input float64) float64 {
	intInput := int64(math.Round(input * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (math.Floor(float64(intInput)/10000) + 1) / 10.0
}

// parseVector splits a CVSS vector into its metrics, requiring one of the
// given version prefixes.
//
// Metrics it does not recognise are kept rather than rejected: temporal and
// environmental metrics are present on 30 live vectors, and they are not
// malformedness. The base score ignores them, and refusing the vector would
// turn a scorable finding into an unrated one — a false negative for every
// --fail-on threshold, arrived at through strictness.
//
// A repeated metric IS rejected. Silently taking the first or the last would
// mean two readers of the same vector could disagree about its score.
func parseVector(vector string, versions ...string) (map[string]string, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: %q is not a CVSS vector", ErrUnscorable, vector)
	}
	ok := false
	for _, v := range versions {
		if parts[0] == v {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("%w: %q is not %s", ErrUnscorable, parts[0],
			strings.Join(versions, " or "))
	}

	metrics := make(map[string]string, len(parts)-1)
	for _, p := range parts[1:] {
		if p == "" {
			// A live v4 vector ends in a trailing separator. The metrics
			// before it are complete and unambiguous, so rejecting it would
			// cost a scorable finding for a typo in someone else's data.
			continue
		}
		key, value, found := strings.Cut(p, ":")
		if !found || key == "" || value == "" {
			return nil, fmt.Errorf("%w: %q in %q is not key:value", ErrUnscorable, p, vector)
		}
		if _, dup := metrics[key]; dup {
			return nil, fmt.Errorf("%w: %q appears twice in %q", ErrUnscorable, key, vector)
		}
		metrics[key] = value
	}
	return metrics, nil
}

// lookup resolves one required metric to its weight.
func lookup(metrics map[string]string, key string, table map[string]float64, vector string) (float64, error) {
	value, ok := metrics[key]
	if !ok {
		return 0, fmt.Errorf("%w: %q has no %s", ErrUnscorable, vector, key)
	}
	weight, ok := table[value]
	if !ok {
		return 0, fmt.Errorf("%w: %s:%s in %q is not a defined value", ErrUnscorable, key, value, vector)
	}
	return weight, nil
}

// lookupCode is lookup for a metric read as a code rather than a weight.
func lookupCode[T any](metrics map[string]string, key string, table map[string]T, vector string) (string, error) {
	value, ok := metrics[key]
	if !ok {
		return "", fmt.Errorf("%w: %q has no %s", ErrUnscorable, vector, key)
	}
	if _, ok := table[value]; !ok {
		return "", fmt.Errorf("%w: %s:%s in %q is not a defined value", ErrUnscorable, key, value, vector)
	}
	return value, nil
}
