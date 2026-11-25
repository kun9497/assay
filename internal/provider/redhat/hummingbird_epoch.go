package redhat

import (
	"strings"

	"github.com/kun9497/assay/internal/advisory"
)

// hummingbirdHold keeps back every record that carries a Hummingbird entry
// until the whole feed has been read, so a fixed build stated without its
// epoch can take the epoch another document states for it.
//
// QA 2026-11-20. Red Hat's feed stopped writing the purl's "epoch" qualifier
// on part of its Hummingbird documents while still writing it on others, for
// the SAME build: cve-2026-95101 and cve-2026-97629 list nginx
// 1.30.6-1.hum1 with no qualifier (and "nginx-0:" in the product id), and
// cve-2026-120993 lists that build with "epoch=2". The installed nginx reads
// 2:1.30.4-2.hum1 from the rpmdb, version.RPM orders the epoch first, and
// every epoch-less fix was therefore below every installed build: clean, no
// skip. One document cannot settle it -- it is self-consistently wrong -- so
// the answer is taken from the feed as a whole, which is why the records are
// held rather than repaired in convert.
//
// A record with the id of one already held is held too, whatever it carries:
// two copies of one document reach the store in the order they were emitted
// (D129, D135), and holding only one of them would reverse that order.
type hummingbirdHold struct {
	held []advisory.Advisory
	ids  map[string]bool
}

// take holds adv and reports true, or reports false for a record the caller
// should emit now.
func (h *hummingbirdHold) take(adv advisory.Advisory) bool {
	if !h.ids[adv.ID] && !carriesHummingbird(adv) {
		return false
	}
	if h.ids == nil {
		h.ids = map[string]bool{}
	}
	h.ids[adv.ID] = true
	h.held = append(h.held, adv)
	return true
}

func carriesHummingbird(adv advisory.Advisory) bool {
	for _, a := range adv.Affected {
		if a.Ecosystem == hummingbirdEcosystem {
			return true
		}
	}
	return false
}

// release restores the epochs and emits what was held, in the order it
// arrived.
//
// Two rules, the exact one first. (1) A build is one rpm: the same name and
// version-release stated with an epoch anywhere in the feed has that epoch
// everywhere. (2) Failing that, a package every epoch-carrying statement in
// the feed puts at ONE epoch takes it -- the shape of a build only the
// epoch-less documents mention. A package seen at two epochs is left as
// written and counted: guessing between them could move a fix below an
// installed build as easily as above it.
//
// Rule 2 errs toward reporting. A package whose early builds truly had no
// epoch would have those fixes raised to the later epoch, and an installed
// epoch-less build would then be reported against a fix it already carries.
// None did on 2026-11-25: every epoch in the database was the one Red Hat's
// Hummingbird repositories give the build. A fix both rules leave without one
// is the matcher's (D176).
func (h *hummingbirdHold) release(st *stats, emit func(advisory.Advisory) error) error {
	type build struct{ name, versionRelease string }
	epochOfBuild := map[build]string{}
	disputed := map[build]bool{}
	epochsOfName := map[string]map[string]bool{}
	eachFixed(h.held, func(name string, fixed *string) {
		epoch, vr, ok := strings.Cut(*fixed, ":")
		if !ok {
			return
		}
		b := build{name, vr}
		if prev, seen := epochOfBuild[b]; seen && prev != epoch {
			disputed[b] = true
		}
		epochOfBuild[b] = epoch
		if epochsOfName[name] == nil {
			epochsOfName[name] = map[string]bool{}
		}
		epochsOfName[name][epoch] = true
	})
	eachFixed(h.held, func(name string, fixed *string) {
		if strings.Contains(*fixed, ":") {
			return
		}
		b := build{name, *fixed}
		if epoch, ok := epochOfBuild[b]; ok && !disputed[b] {
			*fixed = epoch + ":" + *fixed
			st.HummingbirdEpochFromBuild++
			return
		}
		switch epochs := epochsOfName[name]; len(epochs) {
		case 0:
			// No statement in the feed gives this package an epoch: it has
			// none, which is most of Hummingbird.
		case 1:
			for epoch := range epochs {
				*fixed = epoch + ":" + *fixed
			}
			st.HummingbirdEpochFromName++
		default:
			st.HummingbirdEpochUnsettled++
		}
	})
	for _, adv := range h.held {
		if err := emit(adv); err != nil {
			return err
		}
	}
	h.held, h.ids = nil, nil
	return nil
}

// eachFixed calls f with every fixed event on a Hummingbird entry, by
// pointer so f can rewrite it in place.
func eachFixed(advs []advisory.Advisory, f func(name string, fixed *string)) {
	for i := range advs {
		for j := range advs[i].Affected {
			a := &advs[i].Affected[j]
			if a.Ecosystem != hummingbirdEcosystem {
				continue
			}
			for k := range a.Ranges {
				for l := range a.Ranges[k].Events {
					if e := &a.Ranges[k].Events[l]; e.Fixed != "" {
						f(a.Name, &e.Fixed)
					}
				}
			}
		}
	}
}
