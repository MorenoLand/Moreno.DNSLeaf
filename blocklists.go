package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

func isRemoteBlocklistSource(source string) bool {
	return strings.HasPrefix(strings.TrimSpace(source), "http://") || strings.HasPrefix(strings.TrimSpace(source), "https://")
}

const maxBlocklistBytes = 50 * 1024 * 1024
const blocklistCacheMaxAge = 24 * time.Hour

func gravityCacheName(source string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(source)))
	return fmt.Sprintf("%x.list", sum[:])
}

func (d *DNSLeaf) gravityCachePath(source string) string {
	return filepath.Join(d.gravityDir, gravityCacheName(source))
}

func (d *DNSLeaf) readBlocklistSource(source string, forceRemote bool) ([]byte, bool, error) {
	source = strings.TrimSpace(source)
	if !isRemoteBlocklistSource(source) {
		data, err := os.ReadFile(d.runtimePath(source))
		return data, false, err
	}
	cachePath := d.gravityCachePath(source)
	if !forceRemote {
		if info, err := os.Stat(cachePath); err == nil && time.Since(info.ModTime()) < blocklistCacheMaxAge {
			if data, readErr := os.ReadFile(cachePath); readErr == nil {
				return data, true, nil
			}
		}
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(source)
	if err != nil {
		if data, readErr := os.ReadFile(cachePath); readErr == nil {
			return data, true, fmt.Errorf("%w; using cached copy", err)
		}
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("HTTP %d", resp.StatusCode)
		if data, readErr := os.ReadFile(cachePath); readErr == nil {
			return data, true, fmt.Errorf("%w; using cached copy", err)
		}
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBlocklistBytes+1))
	if err != nil {
		if cached, readErr := os.ReadFile(cachePath); readErr == nil {
			return cached, true, fmt.Errorf("%w; using cached copy", err)
		}
		return nil, false, err
	}
	if len(data) > maxBlocklistBytes {
		err := fmt.Errorf("blocklist exceeds %d MiB", maxBlocklistBytes/(1024*1024))
		if cached, readErr := os.ReadFile(cachePath); readErr == nil {
			return cached, true, fmt.Errorf("%w; using cached copy", err)
		}
		return nil, false, err
	}
	if err := os.MkdirAll(d.gravityDir, 0700); err == nil {
		_ = atomicWriteFile(cachePath, data, 0600)
	}
	return data, false, nil
}

func releaseGravityLoadMemory() {
	runtime.GC()
	debug.FreeOSMemory()
}

func parseBlocklist(data []byte) []string {
	var domains []string
	for _, raw := range strings.Split(string(data), "\n") {
		domain := parseBlocklistLine(raw)
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	return domains
}

func parseBlocklistLine(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return ""
	}
	if idx := strings.Index(line, "#"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, "//"); idx > 0 && !strings.Contains(line[:idx], "://") {
		line = strings.TrimSpace(line[:idx])
	}
	if strings.HasPrefix(line, "@@") {
		return ""
	}
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		if idx := strings.IndexAny(line, "^/$*"); idx >= 0 {
			line = line[:idx]
		}
		return normalizeDomainRule(line)
	}
	if strings.HasPrefix(line, "|http://") || strings.HasPrefix(line, "|https://") {
		line = strings.TrimPrefix(line, "|")
		if u, err := url.Parse(line); err == nil {
			return normalizeDomainRule(u.Hostname())
		}
		return ""
	}
	if strings.HasPrefix(line, "address=/") {
		parts := strings.Split(line, "/")
		if len(parts) >= 3 {
			return normalizeDomainRule(parts[1])
		}
	}
	if strings.HasPrefix(line, "server=/") {
		parts := strings.Split(line, "/")
		if len(parts) >= 3 {
			return normalizeDomainRule(parts[1])
		}
	}
	if parts := strings.Fields(line); len(parts) >= 2 {
		if parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1" || parts[0] == "::" || parts[0] == "::1" {
			line = parts[1]
		} else {
			return ""
		}
	}
	line = strings.TrimPrefix(line, "||")
	line = strings.TrimPrefix(line, ".")
	line = strings.Trim(line, "|^")
	domain := normalizeDomainRule(line)
	if domain == "" || strings.ContainsAny(domain, "/?=&") {
		return ""
	}
	return domain
}

func normalizeDomainRule(rule string) string {
	rule = strings.ToLower(strings.TrimSpace(rule))
	if rule == "" {
		return ""
	}
	if strings.HasPrefix(rule, "regex:") || (strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") && len(rule) > 2) {
		return rule
	}
	return strings.TrimSuffix(rule, ".")
}

func ensureRule(rules []string, rule string) []string {
	normalized := normalizeDomainRule(rule)
	for _, existing := range rules {
		if normalizeDomainRule(existing) == normalized {
			return rules
		}
	}
	return append(rules, normalized)
}

func isRegexRule(rule string) bool {
	return strings.HasPrefix(rule, "regex:") || (strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") && len(rule) > 2)
}

func regexRulePattern(rule string) string {
	if strings.HasPrefix(rule, "regex:") {
		return strings.TrimSpace(strings.TrimPrefix(rule, "regex:"))
	}
	if strings.HasPrefix(rule, "/") && strings.HasSuffix(rule, "/") && len(rule) > 2 {
		return strings.TrimSuffix(strings.TrimPrefix(rule, "/"), "/")
	}
	return ""
}

func isPatternRule(rule string) bool {
	return isRegexRule(rule) || strings.Contains(rule, "*")
}

func wildcardRulePattern(rule string) string {
	parts := strings.Split(regexp.QuoteMeta(rule), `\*`)
	return "^" + strings.Join(parts, ".*") + "$"
}

func compileDomainRule(rule string) (*regexp.Regexp, error) {
	rule = normalizeDomainRule(rule)
	if !isPatternRule(rule) {
		return nil, nil
	}
	pattern := rule
	if isRegexRule(rule) {
		pattern = regexRulePattern(rule)
	} else {
		pattern = wildcardRulePattern(rule)
	}
	return regexp.Compile(pattern)
}

func domainRuleMatches(rule, name string) bool {
	rule = normalizeDomainRule(rule)
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if rule == "" || name == "" {
		return false
	}
	if re, err := compileDomainRule(rule); err == nil && re != nil {
		return re.MatchString(name)
	}
	return rule == name
}

func (d *DNSLeaf) domainRuleMatches(rule, name string) bool {
	rule = normalizeDomainRule(rule)
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if rule == "" || name == "" {
		return false
	}
	if !isPatternRule(rule) {
		return rule == name
	}
	d.ruleCacheMu.RLock()
	re := d.ruleCache[rule]
	d.ruleCacheMu.RUnlock()
	if re == nil {
		compiled, err := compileDomainRule(rule)
		if err != nil || compiled == nil {
			return false
		}
		d.ruleCacheMu.Lock()
		if len(d.ruleCache) < maxRuleCache {
			d.ruleCache[rule] = compiled
		}
		d.ruleCacheMu.Unlock()
		re = compiled
	}
	return re.MatchString(name)
}

func validateDomainRule(rule string) error {
	rule = normalizeDomainRule(rule)
	if rule == "" {
		return fmt.Errorf("domain required")
	}
	if len(rule) > maxDomainRuleLen {
		return fmt.Errorf("domain rule must be at most %d bytes", maxDomainRuleLen)
	}
	if isRegexRule(rule) {
		if _, err := compileDomainRule(rule); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		return nil
	}
	if strings.Contains(rule, "*") {
		if _, err := compileDomainRule(rule); err != nil {
			return fmt.Errorf("invalid wildcard: %w", err)
		}
	}
	return nil
}

func (d *DNSLeaf) loadBlocklist() error {
	return d.loadBlocklistFiltered(func(BlocklistSource) bool { return true }, false)
}

func (d *DNSLeaf) loadLocalBlocklists() error {
	err := d.loadBlocklistFiltered(func(src BlocklistSource) bool {
		return !isRemoteBlocklistSource(src.Source)
	}, false)
	if err != nil {
		return err
	}
	return d.saveConfig()
}

func (d *DNSLeaf) loadRemoteBlocklists() error {
	return d.loadBlocklistFiltered(func(src BlocklistSource) bool {
		return isRemoteBlocklistSource(src.Source)
	}, false)
}

func (d *DNSLeaf) refreshBlocklists() error {
	return d.loadBlocklistFiltered(func(BlocklistSource) bool { return true }, true)
}

func (d *DNSLeaf) loadBlocklistFilteredIndex(forceIndex int) error {
	var gravityExact []string
	gravityByList := map[string][]string{}
	for i := range d.cfg.Blocklists {
		src := &d.cfg.Blocklists[i]
		src.LastLoaded = 0
		src.LastError = ""
		if !src.Enabled {
			continue
		}
		if err := d.loadOneBlocklist(i, i == forceIndex, &gravityExact, gravityByList); err != nil {
			return err
		}
	}
	if len(gravityExact) > 0 {
		d.blockMu.Lock()
		d.mergeGravityLocked(gravityExact)
		d.rebuildGravityListIndexesLocked(gravityByList)
		d.blockMu.Unlock()
	}
	releaseGravityLoadMemory()
	return nil
}

func (d *DNSLeaf) refreshBlocklistTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return d.refreshGravity()
	}
	idx, err := d.blocklistIndex(target)
	if err != nil {
		return err
	}
	d.resetBlocked()
	d.initBlocked()
	return d.loadBlocklistFilteredIndex(idx)
}

func (d *DNSLeaf) blocklistIndex(target string) (int, error) {
	target = strings.TrimSpace(target)
	if n, err := strconv.Atoi(target); err == nil {
		if n > 0 && n <= len(d.cfg.Blocklists) {
			return n - 1, nil
		} else if n >= 0 && n < len(d.cfg.Blocklists) {
			return n, nil
		}
	}
	for i, list := range d.cfg.Blocklists {
		if strings.EqualFold(list.Name, target) || strings.EqualFold(list.Source, target) {
			return i, nil
		}
	}
	return -1, fmt.Errorf("blocklist not found: %s", target)
}

func (d *DNSLeaf) hasRemoteBlocklists() bool {
	for _, src := range d.cfg.Blocklists {
		if src.Enabled && isRemoteBlocklistSource(src.Source) {
			return true
		}
	}
	return false
}

func (d *DNSLeaf) loadBlocklistFiltered(include func(BlocklistSource) bool, forceRemote bool) error {
	var gravityExact []string
	gravityByList := map[string][]string{}
	for i := range d.cfg.Blocklists {
		src := &d.cfg.Blocklists[i]
		if !include(*src) {
			continue
		}
		src.LastLoaded = 0
		src.LastError = ""
		if !src.Enabled {
			continue
		}
		if err := d.loadOneBlocklist(i, forceRemote, &gravityExact, gravityByList); err != nil {
			return err
		}
	}
	if len(gravityExact) > 0 {
		d.blockMu.Lock()
		d.mergeGravityLocked(gravityExact)
		d.rebuildGravityListIndexesLocked(gravityByList)
		d.blockMu.Unlock()
	}
	releaseGravityLoadMemory()
	return nil
}

func (d *DNSLeaf) loadOneBlocklist(i int, forceRemote bool, gravityExact *[]string, gravityByList map[string][]string) error {
	src := &d.cfg.Blocklists[i]
	source := strings.TrimSpace(src.Source)
	label := src.Name
	src.LastChecked = time.Now().Format(time.RFC3339)
	src.CacheAge = 0
	if label == "" {
		label = source
	}
	if source == "" {
		src.LastError = "source required"
		src.LastRefreshed = time.Now().Format(time.RFC3339)
		d.gravityLine("skipped empty blocklist source")
		return nil
	}
	d.gravityLine("loading " + label)
	data, fromCache, err := d.readBlocklistSource(source, forceRemote)
	if err != nil {
		if os.IsNotExist(err) {
			d.gravityLine("missing local blocklist " + source)
			return nil
		}
		src.LastError = err.Error()
		if data == nil {
			src.LastRefreshed = time.Now().Format(time.RFC3339)
			d.gravityLine("failed " + label + ": " + err.Error())
			return nil
		}
		d.gravityLine("warning " + label + ": " + err.Error())
	}
	domains := d.applyListAllowlist(parseBlocklist(data), src.Allowlist)
	domains = append(domains, d.groupDomainsForSource(source, src.Groups)...)
	remote := isRemoteBlocklistSource(source)
	listKey := src.Name
	if listKey == "" {
		listKey = source
	}
	var listExact []string
	if remote {
		label = ""
	}
	loaded := 0
	if remote {
		var patterns []string
		for _, domain := range domains {
			if isPatternRule(domain) {
				patterns = append(patterns, domain)
			} else {
				*gravityExact = append(*gravityExact, domain)
				listExact = append(listExact, domain)
				loaded++
			}
		}
		if len(patterns) > 0 {
			d.blockMu.Lock()
			for _, domain := range patterns {
				if d.addBlockedRuleLocked(domain, label) {
					loaded++
				}
			}
			d.blockMu.Unlock()
		}
	} else {
		d.blockMu.Lock()
		for _, domain := range domains {
			if d.addBlockedRuleLocked(domain, label) {
				loaded++
			}
			if !isPatternRule(domain) {
				listExact = append(listExact, domain)
			}
		}
		d.blockMu.Unlock()
	}
	src.LastLoaded = loaded
	src.LastRefreshed = time.Now().Format(time.RFC3339)
	if fromCache {
		if info, statErr := os.Stat(d.gravityCachePath(source)); statErr == nil {
			src.CacheAge = int64(time.Since(info.ModTime()).Seconds())
			if src.CacheAge < 0 {
				src.CacheAge = 0
			}
		}
	}
	if len(listExact) > 0 {
		sort.Strings(listExact)
		n := 0
		for _, domain := range listExact {
			domain = normalizeDomainRule(domain)
			if domain != "" && (n == 0 || listExact[n-1] != domain) {
				listExact[n] = domain
				n++
			}
		}
		exact := append([]string(nil), listExact[:n]...)
		gravityByList[source] = exact
		gravityByList[listKey] = exact
	}
	if fromCache {
		d.gravityLine(fmt.Sprintf("loaded %d domains from %s using cache", loaded, source))
	} else {
		d.gravityLine(fmt.Sprintf("loaded %d domains from %s", loaded, source))
	}
	return nil
}

func (d *DNSLeaf) applyListAllowlist(domains []string, allow []string) []string {
	if len(domains) == 0 || len(allow) == 0 {
		return domains
	}
	out := domains[:0]
	for _, domain := range domains {
		keep := true
		for _, allowed := range allow {
			if d.domainRuleMatches(allowed, domain) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, domain)
		}
	}
	return out
}

func (d *DNSLeaf) groupDomainsForSource(source string, groupNames []string) []string {
	var out []string
	listName := ""
	for _, list := range d.cfg.Blocklists {
		if list.Source == source {
			listName = list.Name
			break
		}
	}
	for _, group := range d.cfg.BlockGroups {
		assigned := false
		for _, src := range group.Sources {
			if src == source || strings.EqualFold(src, listName) {
				assigned = true
				break
			}
		}
		for _, name := range groupNames {
			if strings.EqualFold(name, group.Name) {
				assigned = true
				break
			}
		}
		if assigned {
			out = append(out, group.Domains...)
		}
	}
	return out
}

func (d *DNSLeaf) rebuildBlocklists() error {
	d.resetBlocked()
	d.initBlocked()
	return d.loadBlocklist()
}

func (d *DNSLeaf) refreshGravity() error {
	d.resetBlocked()
	d.initBlocked()
	return d.refreshBlocklists()
}

func (d *DNSLeaf) initBlocked() {
	d.blockMu.Lock()
	defer d.blockMu.Unlock()
	for _, dom := range d.cfg.Blocked {
		d.addBlockedRuleLocked(dom, "config")
	}
}

func (d *DNSLeaf) resetBlocked() {
	d.blockMu.Lock()
	d.blocked = make(map[string]bool)
	d.blockedSrc = make(map[string]string)
	d.blockedPat = nil
	d.gravity = nil
	d.gravityByList = make(map[string][]uint32)
	d.blockMu.Unlock()
}

func (d *DNSLeaf) mergeGravityLocked(domains []string) {
	if len(domains) == 0 {
		return
	}
	all := make([]string, 0, len(d.gravity)+len(domains))
	all = append(all, d.gravity...)
	for _, domain := range domains {
		domain = normalizeDomainRule(domain)
		if domain != "" {
			all = append(all, domain)
		}
	}
	sort.Strings(all)
	n := 0
	for _, domain := range all {
		if n == 0 || all[n-1] != domain {
			all[n] = domain
			n++
		}
	}
	d.gravity = all[:n]
}

func (d *DNSLeaf) gravityContainsLocked(domain string) bool {
	i := sort.SearchStrings(d.gravity, domain)
	return i < len(d.gravity) && d.gravity[i] == domain
}

func (d *DNSLeaf) rebuildGravityListIndexesLocked(lists map[string][]string) {
	d.gravityByList = make(map[string][]uint32, len(lists))
	for key, domains := range lists {
		indexes := make([]uint32, 0, len(domains))
		for _, domain := range domains {
			i := sort.SearchStrings(d.gravity, domain)
			if i < len(d.gravity) && d.gravity[i] == domain && uint64(i) <= uint64(^uint32(0)) {
				indexes = append(indexes, uint32(i))
			}
		}
		if len(indexes) > 0 {
			d.gravityByList[key] = indexes
		}
	}
}

func (d *DNSLeaf) blockedCountLocked() int {
	return len(d.blocked) + len(d.gravity)
}

func (d *DNSLeaf) addBlockedRuleLocked(rule, source string) bool {
	rule = normalizeDomainRule(rule)
	if rule == "" {
		return false
	}
	added := !d.blocked[rule]
	d.blocked[rule] = true
	if source != "" {
		d.blockedSrc[rule] = source
	}
	if isPatternRule(rule) && added {
		d.blockedPat = append(d.blockedPat, rule)
	}
	return added
}

func (d *DNSLeaf) removeBlockedRuleLocked(rule string) {
	rule = normalizeDomainRule(rule)
	delete(d.blocked, rule)
	delete(d.blockedSrc, rule)
	next := d.blockedPat[:0]
	for _, pat := range d.blockedPat {
		if pat != rule {
			next = append(next, pat)
		}
	}
	d.blockedPat = next
}

func (d *DNSLeaf) isBlocked(qname string) bool {
	blocked, _ := d.blockDecision(qname, "")
	return blocked
}

func (d *DNSLeaf) blockDecision(qname, clientIP string) (bool, string) {
	d.blockMu.RLock()
	defer d.blockMu.RUnlock()
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	profileName, profile, hasProfile := d.profileForClientLocked(clientIP)
	profileLimitsBlocklists := hasProfile && len(profile.Blocklists) > 0
	if hasProfile && (profile.DisableBlocking || profile.Disabled) {
		return false, ""
	}
	if hasProfile {
		for _, allow := range profile.Allowed {
			if d.domainRuleMatches(allow, name) {
				return false, ""
			}
		}
		for _, blocked := range profile.Blocked {
			if d.domainRuleMatches(blocked, name) {
				return true, "profile:" + profileName
			}
		}
		if len(profile.Blocklists) > 0 {
			if d.profileBlocklistContainsLocked(profile, name) {
				return true, "profile-list:" + profileName
			}
		}
	}
	for _, allow := range d.cfg.Allowed {
		if d.domainRuleMatches(allow, name) {
			return false, ""
		}
	}
	if action, source := d.scheduledDecisionLocked(name); action != "" {
		return action == "block", source
	}
	if src, ok := d.blockedSrc[name]; ok {
		if profileLimitsBlocklists && d.sourceIsBlocklistLocked(src) && !d.profileHasBlocklistLocked(profile, src) {
			return false, ""
		}
		return true, src
	}
	if d.blocked[name] {
		if profileLimitsBlocklists {
			return false, ""
		}
		return true, "manual"
	}
	if !profileLimitsBlocklists && d.gravityContainsLocked(name) {
		return true, "gravity"
	}
	parts := strings.Split(name, ".")
	for i := 0; i < len(parts)-1; i++ {
		wild := "*." + strings.Join(parts[i+1:], ".")
		if d.blocked[wild] {
			src := d.blockedSrc[wild]
			if profileLimitsBlocklists && d.sourceIsBlocklistLocked(src) && !d.profileHasBlocklistLocked(profile, src) {
				continue
			}
			if profileLimitsBlocklists && src == "" {
				continue
			}
			if src == "" {
				src = "wildcard"
			}
			return true, src
		}
	}
	for _, rule := range d.blockedPat {
		if d.domainRuleMatches(rule, name) {
			src := d.blockedSrc[rule]
			if profileLimitsBlocklists && d.sourceIsBlocklistLocked(src) && !d.profileHasBlocklistLocked(profile, src) {
				continue
			}
			if profileLimitsBlocklists && src == "" {
				continue
			}
			if src == "" {
				src = "regex"
			}
			return true, src
		}
	}
	return false, ""
}

func (d *DNSLeaf) profileForClientLocked(clientIP string) (string, ClientProfile, bool) {
	if d.cfg.Profiles == nil {
		return "", ClientProfile{}, false
	}
	name := ""
	if clientIP != "" {
		if exact := strings.TrimSpace(d.cfg.ClientProfiles[clientIP]); exact != "" {
			name = exact
		}
		if name == "" {
			for rule, profile := range d.cfg.ClientProfiles {
				if strings.Contains(rule, "/") && ipInList(clientIP, []string{rule}) {
					name = strings.TrimSpace(profile)
					break
				}
			}
		}
	}
	if name == "" {
		name = strings.TrimSpace(d.cfg.DefaultProfile)
	}
	if name == "" {
		name = "default"
	}
	profile, ok := d.cfg.Profiles[name]
	return name, profile, ok
}

func (d *DNSLeaf) profileForClient(clientIP string) (string, ClientProfile, bool) {
	d.blockMu.RLock()
	defer d.blockMu.RUnlock()
	return d.profileForClientLocked(clientIP)
}

func (d *DNSLeaf) profileBlocklistContainsLocked(profile ClientProfile, name string) bool {
	for _, list := range profile.Blocklists {
		list = strings.TrimSpace(list)
		if list == "" {
			continue
		}
		if indexes := d.gravityByList[list]; len(indexes) > 0 {
			if d.gravityIndexSetContainsLocked(indexes, name) {
				return true
			}
		}
		for _, src := range d.cfg.Blocklists {
			if strings.EqualFold(src.Name, list) || strings.EqualFold(src.Source, list) {
				if indexes := d.gravityByList[src.Source]; len(indexes) > 0 {
					if d.gravityIndexSetContainsLocked(indexes, name) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (d *DNSLeaf) gravityIndexSetContainsLocked(indexes []uint32, name string) bool {
	i := sort.SearchStrings(d.gravity, name)
	if i >= len(d.gravity) || d.gravity[i] != name || uint64(i) > uint64(^uint32(0)) {
		return false
	}
	needle := uint32(i)
	j := sort.Search(len(indexes), func(n int) bool { return indexes[n] >= needle })
	return j < len(indexes) && indexes[j] == needle
}

func (d *DNSLeaf) sourceIsBlocklistLocked(source string) bool {
	for _, src := range d.cfg.Blocklists {
		if strings.EqualFold(src.Name, source) || strings.EqualFold(src.Source, source) {
			return true
		}
	}
	return false
}

func (d *DNSLeaf) profileHasBlocklistLocked(profile ClientProfile, source string) bool {
	for _, item := range profile.Blocklists {
		item = strings.TrimSpace(item)
		if strings.EqualFold(item, source) {
			return true
		}
		for _, src := range d.cfg.Blocklists {
			if (strings.EqualFold(src.Name, item) || strings.EqualFold(src.Source, item)) && (strings.EqualFold(src.Name, source) || strings.EqualFold(src.Source, source)) {
				return true
			}
		}
	}
	return false
}

func (d *DNSLeaf) scheduledDecisionLocked(name string) (string, string) {
	now := time.Now()
	for _, rule := range d.cfg.ScheduledRules {
		if !rule.Enabled || !d.domainRuleMatches(rule.Domain, name) || !scheduledRuleActive(rule, now) {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action == "allow" || action == "block" {
			return action, "schedule:" + rule.Domain
		}
	}
	return "", ""
}

func scheduledRuleActive(rule ScheduledRule, now time.Time) bool {
	if len(rule.Days) > 0 {
		day := strings.ToLower(now.Weekday().String()[:3])
		ok := false
		for _, item := range rule.Days {
			if strings.ToLower(strings.TrimSpace(item)) == day {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	start, ok1 := parseClock(rule.Start)
	end, ok2 := parseClock(rule.End)
	if !ok1 || !ok2 {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	if start <= end {
		return cur >= start && cur <= end
	}
	return cur >= start || cur <= end
}

func parseClock(s string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) < 2 {
		return 0, false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}
