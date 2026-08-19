package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (d *DNSLeaf) handleBlocked(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		d.blockMu.RLock()
		entries := make([]BlockedEntry, 0, d.blockedCountLocked())
		for dom := range d.blocked {
			src := d.blockedSrc[dom]
			if src == "" {
				src = "manual"
			}
			entries = append(entries, BlockedEntry{Domain: dom, Source: src})
		}
		for _, dom := range d.gravity {
			entries = append(entries, BlockedEntry{Domain: dom, Source: "gravity"})
		}
		d.blockMu.RUnlock()
		writeJSON(w, entries)
	case "POST":
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		domain := normalizeDomainRule(body.Domain)
		if err := validateDomainRule(domain); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		d.blockMu.Lock()
		d.addBlockedRuleLocked(domain, "config")
		d.blockMu.Unlock()
		exists := false
		for _, existing := range d.cfg.Blocked {
			if normalizeDomainRule(existing) == domain {
				exists = true
				break
			}
		}
		if !exists {
			d.cfg.Blocked = append(d.cfg.Blocked, domain)
		}
		writeJSON(w, map[string]string{"domain": domain})
	case "DELETE":
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		domain := normalizeDomainRule(body.Domain)
		d.blockMu.Lock()
		d.removeBlockedRuleLocked(domain)
		d.blockMu.Unlock()
		next := d.cfg.Blocked[:0]
		for _, dom := range d.cfg.Blocked {
			if normalizeDomainRule(dom) != domain {
				next = append(next, dom)
			}
		}
		d.cfg.Blocked = next
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleAllowed(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.Allowed)
	case "POST":
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		domain := normalizeDomainRule(body.Domain)
		if err := validateDomainRule(domain); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for _, existing := range d.cfg.Allowed {
			if normalizeDomainRule(existing) == domain {
				writeJSON(w, map[string]string{"domain": domain})
				return
			}
		}
		d.cfg.Allowed = append(d.cfg.Allowed, domain)
		writeJSON(w, map[string]string{"domain": domain})
	case "DELETE":
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		domain := normalizeDomainRule(body.Domain)
		next := d.cfg.Allowed[:0]
		for _, existing := range d.cfg.Allowed {
			if normalizeDomainRule(existing) != domain {
				next = append(next, existing)
			}
		}
		d.cfg.Allowed = next
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.BlockedIPs)
	case "POST":
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ip, err := normalizeIPOrCIDR(body.IP)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for _, existing := range d.cfg.BlockedIPs {
			normalizedExisting, _ := normalizeIPOrCIDR(existing)
			if normalizedExisting == ip {
				writeJSON(w, map[string]string{"ip": ip})
				return
			}
		}
		d.cfg.BlockedIPs = append(d.cfg.BlockedIPs, ip)
		writeJSON(w, map[string]string{"ip": ip})
	case "DELETE":
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ip, err := normalizeIPOrCIDR(body.IP)
		if err != nil {
			ip = strings.TrimSpace(body.IP)
		}
		next := d.cfg.BlockedIPs[:0]
		for _, existing := range d.cfg.BlockedIPs {
			normalizedExisting, _ := normalizeIPOrCIDR(existing)
			if existing != ip && normalizedExisting != ip {
				next = append(next, existing)
			}
		}
		d.cfg.BlockedIPs = next
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleRegexRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		d.blockMu.RLock()
		out := append([]string(nil), d.blockedPat...)
		d.blockMu.RUnlock()
		writeJSON(w, out)
	case "POST":
		var body struct {
			Rule string `json:"rule"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rule := normalizeDomainRule(body.Rule)
		if !isPatternRule(rule) {
			http.Error(w, "regex or wildcard rule required", 400)
			return
		}
		if err := validateDomainRule(rule); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		d.blockMu.Lock()
		d.addBlockedRuleLocked(rule, "regex")
		d.blockMu.Unlock()
		d.cfg.Blocked = ensureRule(d.cfg.Blocked, rule)
		writeJSON(w, map[string]string{"rule": rule})
	case "DELETE":
		var body struct {
			Rule string `json:"rule"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rule := normalizeDomainRule(body.Rule)
		d.blockMu.Lock()
		d.removeBlockedRuleLocked(rule)
		d.blockMu.Unlock()
		next := d.cfg.Blocked[:0]
		for _, item := range d.cfg.Blocked {
			if normalizeDomainRule(item) != rule {
				next = append(next, item)
			}
		}
		d.cfg.Blocked = next
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.Blocklists)
	case "POST":
		var body BlocklistSource
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		body.Source = strings.TrimSpace(body.Source)
		if body.Source == "" {
			http.Error(w, "source required", 400)
			return
		}
		if body.Name == "" {
			body.Name = body.Source
		}
		body.Enabled = true
		d.cfg.Blocklists = append(d.cfg.Blocklists, body)
		if err := d.rebuildBlocklists(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, d.cfg.Blocklists[len(d.cfg.Blocklists)-1])
	case "PATCH":
		var body BlocklistSource
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		source := strings.TrimSpace(body.Source)
		if source == "" {
			http.Error(w, "source required", 400)
			return
		}
		for i := range d.cfg.Blocklists {
			if d.cfg.Blocklists[i].Source == source {
				if strings.TrimSpace(body.Name) != "" {
					d.cfg.Blocklists[i].Name = strings.TrimSpace(body.Name)
				}
				d.cfg.Blocklists[i].Enabled = body.Enabled
				if body.Allowlist != nil {
					next := make([]string, 0, len(body.Allowlist))
					for _, item := range body.Allowlist {
						item = normalizeDomainRule(item)
						if item != "" {
							next = append(next, item)
						}
					}
					d.cfg.Blocklists[i].Allowlist = next
				}
				if body.Groups != nil {
					d.cfg.Blocklists[i].Groups = cleanNames(body.Groups)
				}
				if err := d.rebuildBlocklists(); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				writeJSON(w, d.cfg.Blocklists[i])
				return
			}
		}
		http.Error(w, "blocklist not found", 404)
	case "DELETE":
		var body struct {
			Source string `json:"source"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		source := strings.TrimSpace(body.Source)
		next := d.cfg.Blocklists[:0]
		found := false
		for _, item := range d.cfg.Blocklists {
			if item.Source == source {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			http.Error(w, "blocklist not found", 404)
			return
		}
		d.cfg.Blocklists = next
		if err := d.rebuildBlocklists(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleBlocklistEntries(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	if source == "" {
		http.Error(w, "source required", 400)
		return
	}
	label := source
	for _, list := range d.cfg.Blocklists {
		if strings.EqualFold(list.Source, source) || strings.EqualFold(list.Name, source) {
			source = list.Source
			if list.Name != "" {
				label = list.Name
			} else {
				label = list.Source
			}
			break
		}
	}
	d.blockMu.RLock()
	entries := make([]BlockedEntry, 0)
	added := map[string]bool{}
	if indexes := d.gravityByList[source]; len(indexes) > 0 {
		entries = make([]BlockedEntry, 0, len(indexes))
		for _, idx := range indexes {
			if int(idx) >= len(d.gravity) {
				continue
			}
			domain := d.gravity[idx]
			if domain == "" || added[domain] {
				continue
			}
			added[domain] = true
			entries = append(entries, BlockedEntry{Domain: domain, Source: label})
		}
	}
	for domain, src := range d.blockedSrc {
		if added[domain] {
			continue
		}
		if strings.EqualFold(src, source) || strings.EqualFold(src, label) {
			added[domain] = true
			entries = append(entries, BlockedEntry{Domain: domain, Source: label})
		}
	}
	d.blockMu.RUnlock()
	writeJSON(w, entries)
}

func cleanNames(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[strings.ToLower(item)] {
			continue
		}
		seen[strings.ToLower(item)] = true
		out = append(out, item)
	}
	return out
}

func cleanRules(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = normalizeDomainRule(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func (d *DNSLeaf) handleBlockGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.BlockGroups)
	case "POST":
		var body struct {
			OldName string   `json:"old_name"`
			Name    string   `json:"name"`
			Domains []string `json:"domains"`
			Sources []string `json:"sources"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			http.Error(w, "name required", 400)
			return
		}
		group := BlockGroup{Name: name, Domains: cleanRules(body.Domains), Sources: cleanNames(body.Sources)}
		match := strings.TrimSpace(body.OldName)
		if match == "" {
			match = name
		}
		for i := range d.cfg.BlockGroups {
			if strings.EqualFold(d.cfg.BlockGroups[i].Name, match) {
				old := d.cfg.BlockGroups[i].Name
				d.cfg.BlockGroups[i] = group
				if old != name {
					for li := range d.cfg.Blocklists {
						for gi, g := range d.cfg.Blocklists[li].Groups {
							if strings.EqualFold(g, old) {
								d.cfg.Blocklists[li].Groups[gi] = name
							}
						}
					}
				}
				if err := d.rebuildBlocklists(); err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				writeJSON(w, d.cfg.BlockGroups[i])
				return
			}
		}
		d.cfg.BlockGroups = append(d.cfg.BlockGroups, group)
		if err := d.rebuildBlocklists(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, group)
	case "DELETE":
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		name := strings.TrimSpace(body.Name)
		next := d.cfg.BlockGroups[:0]
		found := false
		for _, group := range d.cfg.BlockGroups {
			if strings.EqualFold(group.Name, name) {
				found = true
				continue
			}
			next = append(next, group)
		}
		if !found {
			http.Error(w, "group not found", 404)
			return
		}
		d.cfg.BlockGroups = next
		for i := range d.cfg.Blocklists {
			groups := d.cfg.Blocklists[i].Groups[:0]
			for _, group := range d.cfg.Blocklists[i].Groups {
				if !strings.EqualFold(group, name) {
					groups = append(groups, group)
				}
			}
			d.cfg.Blocklists[i].Groups = groups
		}
		if err := d.rebuildBlocklists(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}
