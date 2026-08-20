package amazon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// DefaultExtrasBaseURL is AL2's extras root (D78): <base>/extras-catalog-x86_64.json
// enumerates every topic, and <base>/extras/<topic>/latest/x86_64/mirror.list
// resolves each one through the identical mirror.list -> repomd.xml ->
// updateinfo.xml.gz chain DefaultRepos' two CORE entries already use
// (resolveMirror, updateinfoHref) -- x86_64 only, matching how DefaultRepos
// itself is fetched; no aarch64 catalog is read.
const DefaultExtrasBaseURL = "https://cdn.amazonlinux.com/2"

// extrasCatalogPath is appended to the base to name the topic list.
const extrasCatalogPath = "/extras-catalog-x86_64.json"

// extrasCatalogDoc is the handful of extras-catalog-x86_64.json that Fetch
// needs: each topic's short name. The real document (measured live
// 2026-08-20, 73 topics) also carries "motd", "status", "version" and a
// top-level "whitelists" table, and each topic carries "inst", "versions",
// "deprecated-at" and sometimes "visible" -- all read and discarded by
// encoding/json because extrasTopic has no matching field for them, the same
// "no allowlist to keep in sync" reasoning repomdXML's own doc comment gives
// for repomd.xml's other <data> entries.
type extrasCatalogDoc struct {
	Topics []extrasTopic `json:"topics"`
}

type extrasTopic struct {
	// Name is "n" in the real document ("docker", "livepatch", "ecs", ...),
	// not "name" -- verified directly against the live catalog 2026-08-20.
	Name string `json:"n"`
}

// errNoUpdateinfo signals that repomd.xml named no updateinfo entry at all --
// distinct from a network or parse failure. Measured live 2026-08-20: 14 of
// 73 AL2 extras topics (emacs, nginx1.12, python3, rust1, golang1.9, php7.1,
// epel, testing, kernel-ng, BCC, dnsmasq2.85, lustre, nano, postgresql10)
// take this path, because the topic has never published a security update --
// not because anything is broken. It is exactly as legitimate a zero as an
// updateinfo.xml.gz that decodes to zero <update> elements, the OTHER 14
// zero-advisory topics measured the same day, so fetchRepo treats both
// identically for a Repo with Extras set (see fetchRepo's own handling and
// Repo.Extras' doc comment). A CORE repo is never expected to take this path
// -- every core repo carries an updateinfo entry, measured on both live
// feeds -- so updateinfoHref still surfaces it as an ordinary error there.
var errNoUpdateinfo = errors.New("repomd.xml names no updateinfo entry")

// fetchExtrasTopics enumerates AL2's extras catalog and returns every named
// topic, in the catalog's own order. A topic with an empty "n" is skipped
// rather than turned into a mirror.list URL that could only 404.
func (p *Provider) fetchExtrasTopics(ctx context.Context) ([]string, error) {
	body, err := p.get(ctx, p.extrasBaseURL+extrasCatalogPath)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var doc extrasCatalogDoc
	if err := json.NewDecoder(body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode extras catalog: %w", err)
	}
	topics := make([]string, 0, len(doc.Topics))
	for _, t := range doc.Topics {
		if t.Name == "" {
			continue
		}
		topics = append(topics, t.Name)
	}
	return topics, nil
}

// extrasMirrorListURL builds one topic's mirror.list URL from the same base
// fetchExtrasTopics read the catalog from -- the x86_64 "latest" alias every
// topic publishes, exactly like DefaultRepos' two CORE entries name their own
// mirror.list directly rather than a resolved path (resolveMirror's own doc
// comment explains why the resolved segment can never be cached).
func (p *Provider) extrasMirrorListURL(topic string) string {
	return p.extrasBaseURL + "/extras/" + topic + "/latest/x86_64/mirror.list"
}
