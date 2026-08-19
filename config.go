package main

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func defaultConfig() Config {
	return Config{
		SchemaVersion:      currentConfigSchema,
		Listen:             ":53",
		HTTP:               "127.0.0.1:8080",
		HTTPS:              "",
		TLSCert:            "",
		TLSKey:             "",
		Upstreams:          []string{"1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"},
		DisabledUpstreams:  []string{},
		Records:            []Record{{IP: "192.168.1.1", Host: "router"}},
		Blocked:            []string{},
		BlockedIPs:         []string{},
		Allowed:            []string{},
		Blocklist:          "blocklist.txt",
		Blocklists:         []BlocklistSource{{Name: "Local blocklist", Source: "blocklist.txt", Enabled: true}},
		UpstreamEndpoints:  []UpstreamEndpoint{},
		BlockGroups:        []BlockGroup{},
		Cache:              true,
		CacheSize:          1000,
		CacheTTL:           300,
		StripECS:           true,
		QueryLogEnabled:    true,
		QueryLogRetention:  168,
		AnonymizeClientIPs: false,
		PortalHost:         "dns.leaf",
		PortalIP:           "127.0.0.1",
		LANOnly:            true,
		WhitelistOnly:      false,
		Whitelist:          []string{},
		ClientNames:        map[string]string{},
		ClientProfiles:     map[string]string{},
		DefaultProfile:     "default",
		Profiles:           map[string]ClientProfile{},
		ScheduledRules:     []ScheduledRule{},
		DoT:                "",
		RateLimit:          RateLimitConfig{Enabled: false, Queries: 120, Window: 60, Action: "nxdomain"},
		Anomaly:            AnomalyConfig{Enabled: true, Hits: 25, Window: 60},
		ConditionalForward: []ConditionalForward{},
		DHCPLeasesFile:     "",
		UpstreamHealth:     UpstreamHealthConfig{Enabled: true, Interval: 30, Timeout: 1200, Failures: 3},
		DirectOverride:     false,
		DirectOverrideTo:   "dns.leaf",
		TrollMode:          false,
		TrollHosts:         []string{"4chan.org", "neopets.com", "homestarrunner.com", "theonion.com", "archive.org", "wikipedia.org"},
		TrollIPv4:          []string{},
		TrollIPv6:          []string{},
		HTTPProxyEnabled:   false,
		HTTPProxy:          "",
		SOCKSProxyEnabled:  false,
		SOCKSProxy:         "",
		Auth:               AuthConfig{Enabled: true, Users: []UserAuth{}},
	}
}

func webURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://localhost" + addr
	}
	return "http://" + addr
}

func ensureBuiltinProfiles(cfg *Config) {
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]ClientProfile{}
	}
	if _, ok := cfg.Profiles["default"]; !ok {
		cfg.Profiles["default"] = ClientProfile{Blocked: []string{}, Allowed: []string{}}
	}
	if _, ok := cfg.Profiles["off"]; !ok {
		cfg.Profiles["off"] = ClientProfile{DisableBlocking: true, Blocked: []string{}, Allowed: []string{}}
	}
	if strings.TrimSpace(cfg.DefaultProfile) == "" {
		cfg.DefaultProfile = "default"
	}
}

func portalURL(host, httpsAddr, httpAddr string) string {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		host = "dns.leaf"
	}
	scheme := "http"
	addr := httpAddr
	if strings.TrimSpace(httpsAddr) != "" {
		scheme = "https"
		addr = httpsAddr
	}
	port := ""
	if _, p, err := net.SplitHostPort(addr); err == nil {
		if (scheme == "http" && p != "80") || (scheme == "https" && p != "443") {
			port = ":" + p
		}
	}
	return scheme + "://" + host + port
}

func randomToken(bytes int) string {
	buf := make([]byte, bytes)
	if _, err := io.ReadFull(crand.Reader, buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func passwordHash(password string) string {
	salt := randomToken(18)
	sum := pbkdf2SHA256([]byte(password), []byte(salt), 120000, 32)
	return fmt.Sprintf("pbkdf2-sha256$120000$%s$%s", salt, base64.RawURLEncoding.EncodeToString(sum))
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[1], "%d", &iterations); err != nil || iterations < 10000 {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), []byte(parts[2]), iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	for block := 1; block <= numBlocks; block++ {
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac = hmac.New(sha256.New, password)
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

const (
	maxCacheEntries   = 1000000
	maxCacheTTL       = 7 * 24 * 60 * 60
	maxTrackedClients = 10000
	maxSeenSources    = 4096
	maxRateEntries    = 10000
	maxAnomalyEntries = 10000
	maxLoginEntries   = 10000
	maxSessions       = 1024
	maxRuleCache      = 4096
	maxDomainRuleLen  = 4096
)

func validateConfig(cfg Config) error {
	var issues []string
	add := func(field, message string) { issues = append(issues, field+" "+message) }
	if cfg.SchemaVersion != currentConfigSchema {
		add("schema_version", fmt.Sprintf("must be %d", currentConfigSchema))
	}
	if err := validateNetworkAddress(cfg.Listen, true); err != nil {
		add("listen", err.Error())
	}
	if err := validateNetworkAddress(cfg.HTTP, true); err != nil {
		add("http", err.Error())
	}
	if strings.TrimSpace(cfg.HTTP) == "" {
		add("http", "is required")
	}
	if strings.TrimSpace(cfg.HTTPS) != "" {
		if err := validateNetworkAddress(cfg.HTTPS, true); err != nil {
			add("https", err.Error())
		}
	}
	if strings.TrimSpace(cfg.DoT) != "" {
		if err := validateNetworkAddress(cfg.DoT, true); err != nil {
			add("dot", err.Error())
		}
	}
	if (strings.TrimSpace(cfg.HTTPS) != "" || strings.TrimSpace(cfg.DoT) != "") && (strings.TrimSpace(cfg.TLSCert) == "" || strings.TrimSpace(cfg.TLSKey) == "") {
		add("tls", "certificate and key paths are required when HTTPS or DoT is enabled")
	}
	if len(cfg.Upstreams) == 0 && len(cfg.UpstreamEndpoints) == 0 && !cfg.ResolverDisabled {
		add("upstreams", "at least one upstream or upstream endpoint is required unless resolver_disabled is enabled")
	}
	for i, upstream := range cfg.Upstreams {
		if err := validateNetworkAddress(upstream, false); err != nil {
			add(fmt.Sprintf("upstreams[%d]", i), err.Error())
		}
	}
	for i, endpoint := range cfg.UpstreamEndpoints {
		if err := validateUpstreamEndpoint(endpoint); err != nil {
			add(fmt.Sprintf("upstream_endpoints[%d]", i), err.Error())
		}
	}
	for i, upstream := range cfg.DisabledUpstreams {
		if err := validateNetworkAddress(upstream, false); err != nil {
			add(fmt.Sprintf("disabled_upstreams[%d]", i), err.Error())
		}
	}
	for i, record := range cfg.Records {
		if err := validateRecord(record); err != nil {
			add(fmt.Sprintf("records[%d]", i), err.Error())
		}
	}
	if cfg.CacheSize < 0 || cfg.CacheSize > maxCacheEntries {
		add("cache_size", fmt.Sprintf("must be between 0 and %d", maxCacheEntries))
	}
	if cfg.Cache && (cfg.CacheSize <= 0 || cfg.CacheTTL <= 0) {
		add("cache", "cache_size and cache_ttl_seconds must be positive when caching is enabled")
	}
	if cfg.CacheTTL < 0 || cfg.CacheTTL > maxCacheTTL {
		add("cache_ttl_seconds", fmt.Sprintf("must be between 0 and %d", maxCacheTTL))
	}
	if cfg.QueryLogRetention < 0 || cfg.QueryLogRetention > 24*365 {
		add("query_log_retention_hours", "must be between 0 and 8760")
	}
	if cfg.QueryLogEnabled && cfg.QueryLogRetention <= 0 {
		add("query_log_retention_hours", "must be positive when query logging is enabled")
	}
	if !validDNSName(cfg.PortalHost) {
		add("portal_host", "must be a valid DNS name")
	}
	if net.ParseIP(strings.TrimSpace(cfg.PortalIP)) == nil {
		add("portal_ip", "must be a valid IP address")
	}
	for i, item := range cfg.Whitelist {
		if _, err := normalizeIPOrCIDR(item); err != nil {
			add(fmt.Sprintf("whitelist[%d]", i), err.Error())
		}
	}
	for i, item := range cfg.BlockedIPs {
		if _, err := normalizeIPOrCIDR(item); err != nil {
			add(fmt.Sprintf("blocked_ips[%d]", i), err.Error())
		}
	}
	if cfg.RateLimit.Queries < 0 || cfg.RateLimit.Window < 0 {
		add("rate_limit", "queries and window_seconds cannot be negative")
	}
	if cfg.RateLimit.Enabled && (cfg.RateLimit.Queries <= 0 || cfg.RateLimit.Window <= 0) {
		add("rate_limit", "queries and window_seconds must be positive when enabled")
	}
	if action := strings.ToLower(strings.TrimSpace(cfg.RateLimit.Action)); action != "" && action != "nxdomain" && action != "drop" {
		add("rate_limit.action", "must be nxdomain or drop")
	}
	if cfg.Anomaly.Hits < 0 || cfg.Anomaly.Window < 0 {
		add("anomaly", "hits and window_seconds cannot be negative")
	}
	if cfg.Anomaly.Enabled && (cfg.Anomaly.Hits <= 0 || cfg.Anomaly.Window <= 0) {
		add("anomaly", "hits and window_seconds must be positive when enabled")
	}
	if cfg.UpstreamHealth.Interval < 0 || cfg.UpstreamHealth.Timeout < 0 || cfg.UpstreamHealth.Failures < 0 {
		add("upstream_health", "interval, timeout, and failures cannot be negative")
	}
	if cfg.UpstreamHealth.Enabled && (cfg.UpstreamHealth.Interval <= 0 || cfg.UpstreamHealth.Timeout <= 0 || cfg.UpstreamHealth.Failures <= 0) {
		add("upstream_health", "interval, timeout, and failures must be positive when enabled")
	}
	if cfg.DirectOverrideTo != "" && !validDNSName(cfg.DirectOverrideTo) {
		add("direct_override_to", "must be a valid DNS name")
	}
	for i, rule := range cfg.ConditionalForward {
		if !validDNSName(rule.Suffix) {
			add(fmt.Sprintf("conditional_forwarding[%d].suffix", i), "must be a valid DNS name")
		}
		if len(rule.Upstreams) == 0 {
			add(fmt.Sprintf("conditional_forwarding[%d].upstreams", i), "must not be empty")
		}
		for j, upstream := range rule.Upstreams {
			if err := validateNetworkAddress(upstream, false); err != nil {
				add(fmt.Sprintf("conditional_forwarding[%d].upstreams[%d]", i, j), err.Error())
			}
		}
	}
	for i, item := range cfg.TrollIPv4 {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil || ip.To4() == nil {
			add(fmt.Sprintf("troll_ipv4[%d]", i), "must be an IPv4 address")
		}
	}
	for i, item := range cfg.TrollIPv6 {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil || ip.To4() != nil {
			add(fmt.Sprintf("troll_ipv6[%d]", i), "must be an IPv6 address")
		}
	}
	seenUsers := map[string]bool{}
	for i, user := range cfg.Auth.Users {
		if !validUsername(user.Username) {
			add(fmt.Sprintf("auth.users[%d].username", i), "is invalid")
		}
		key := strings.ToLower(user.Username)
		if seenUsers[key] {
			add(fmt.Sprintf("auth.users[%d].username", i), "is duplicated")
		}
		seenUsers[key] = true
		if user.Role != "admin" && user.Role != "viewer" {
			add(fmt.Sprintf("auth.users[%d].role", i), "must be admin or viewer")
		}
		if strings.TrimSpace(user.PasswordHash) == "" {
			add(fmt.Sprintf("auth.users[%d].password_hash", i), "is required")
		}
	}
	if len(issues) > 0 {
		return fmt.Errorf("invalid configuration: %s", strings.Join(issues, "; "))
	}
	return nil
}

func migrateConfig(cfg *Config) error {
	if cfg.SchemaVersion > currentConfigSchema {
		return fmt.Errorf("configuration schema %d is newer than supported schema %d", cfg.SchemaVersion, currentConfigSchema)
	}
	if cfg.SchemaVersion == 0 {
		cfg.SchemaVersion = currentConfigSchema
	}
	return nil
}

func validateNetworkAddress(value string, allowEmptyHost bool) error {
	value = strings.TrimSpace(value)
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("must be host:port")
	}
	if !allowEmptyHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("host is required")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

type upstreamRoute struct {
	scheme     string
	address    string
	url        string
	serverName string
}

func parseUpstreamEndpoint(endpoint UpstreamEndpoint) (upstreamRoute, error) {
	route := upstreamRoute{}
	raw := strings.TrimSpace(endpoint.URL)
	if raw == "" {
		return route, fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return route, fmt.Errorf("must be a URL with a supported scheme")
	}
	route.scheme = strings.ToLower(u.Scheme)
	switch route.scheme {
	case "udp", "tcp", "tls":
		if u.Path != "" || u.RawQuery != "" {
			return route, fmt.Errorf("%s endpoint cannot contain a path or query", route.scheme)
		}
		port := u.Port()
		if port == "" {
			if route.scheme == "tls" {
				port = "853"
			} else {
				port = "53"
			}
		}
		route.address = net.JoinHostPort(u.Hostname(), port)
		if err := validateNetworkAddress(route.address, false); err != nil {
			return route, err
		}
		if route.scheme == "tls" {
			route.serverName = strings.TrimSpace(endpoint.ServerName)
			if route.serverName == "" {
				route.serverName = u.Hostname()
			}
			if net.ParseIP(route.serverName) != nil {
				if strings.TrimSpace(endpoint.ServerName) == "" {
					return route, fmt.Errorf("server_name is required when a TLS endpoint uses an IP address")
				}
			} else if !validDNSName(route.serverName) {
				return route, fmt.Errorf("server_name must be a valid DNS name")
			}
		}
	case "https":
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		if net.ParseIP(u.Hostname()) == nil && !validDNSName(u.Hostname()) {
			return route, fmt.Errorf("host must be a valid DNS name or IP address")
		}
		if serverName := strings.TrimSpace(endpoint.ServerName); serverName != "" && net.ParseIP(serverName) == nil && !validDNSName(serverName) {
			return route, fmt.Errorf("server_name must be a valid DNS name")
		}
		route.url = u.String()
		route.serverName = strings.TrimSpace(endpoint.ServerName)
	default:
		return route, fmt.Errorf("scheme must be udp, tcp, tls, or https")
	}
	return route, nil
}

func validateUpstreamEndpoint(endpoint UpstreamEndpoint) error {
	_, err := parseUpstreamEndpoint(endpoint)
	return err
}

func validDNSName(value string) bool {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" {
		return false
	}
	_, ok := dns.IsDomainName(dns.Fqdn(value))
	return ok
}

func validateRecord(record Record) error {
	host := strings.TrimSuffix(strings.TrimSpace(record.Host), ".")
	if !validDNSName(host) {
		return fmt.Errorf("host is invalid")
	}
	value := strings.TrimSpace(record.Value)
	if value == "" {
		value = strings.TrimSpace(record.IP)
	}
	if value == "" {
		return fmt.Errorf("value is required")
	}
	recordType := strings.ToUpper(strings.TrimSpace(record.Type))
	if recordType == "" {
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				recordType = "A"
			} else {
				recordType = "AAAA"
			}
		} else {
			return fmt.Errorf("type is required for non-IP values")
		}
	}
	switch recordType {
	case "A":
		if ip := net.ParseIP(value); ip == nil || ip.To4() == nil {
			return fmt.Errorf("A value must be an IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(value); ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA value must be an IPv6 address")
		}
	case "TXT":
		if len(value) > 255 {
			return fmt.Errorf("TXT value must be at most 255 bytes")
		}
	case "CNAME", "MX", "SRV", "PTR":
		if !validDNSName(value) {
			return fmt.Errorf("%s value must be a valid DNS name", recordType)
		}
	case "HTTPS", "SVCB":
		if _, err := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", dns.Fqdn(host), recordType, value)); err != nil {
			return fmt.Errorf("%s value is invalid: %w", recordType, err)
		}
	default:
		return fmt.Errorf("unsupported record type %q", recordType)
	}
	return nil
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	if err == nil {
		if migrationErr := migrateConfig(&cfg); migrationErr != nil {
			return cfg, migrationErr
		}
	}
	if cfg.ClientNames == nil {
		cfg.ClientNames = map[string]string{}
	}
	if cfg.DisabledUpstreams == nil {
		cfg.DisabledUpstreams = []string{}
	}
	if cfg.Whitelist == nil {
		cfg.Whitelist = []string{}
	}
	if cfg.Blocklists == nil {
		cfg.Blocklists = []BlocklistSource{}
	}
	if cfg.BlockGroups == nil {
		cfg.BlockGroups = []BlockGroup{}
	}
	if cfg.Allowed == nil {
		cfg.Allowed = []string{}
	}
	if cfg.BlockedIPs == nil {
		cfg.BlockedIPs = []string{}
	}
	if cfg.ClientProfiles == nil {
		cfg.ClientProfiles = map[string]string{}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]ClientProfile{}
	}
	if strings.TrimSpace(cfg.DefaultProfile) == "" {
		cfg.DefaultProfile = "default"
	}
	ensureBuiltinProfiles(&cfg)
	if cfg.ScheduledRules == nil {
		cfg.ScheduledRules = []ScheduledRule{}
	}
	if cfg.ConditionalForward == nil {
		cfg.ConditionalForward = []ConditionalForward{}
	}
	if cfg.RateLimit.Queries == 0 {
		cfg.RateLimit = RateLimitConfig{Enabled: false, Queries: 120, Window: 60, Action: "nxdomain"}
	}
	if cfg.Anomaly.Hits == 0 {
		cfg.Anomaly = AnomalyConfig{Enabled: true, Hits: 25, Window: 60}
	}
	if cfg.UpstreamHealth.Interval == 0 {
		cfg.UpstreamHealth = UpstreamHealthConfig{Enabled: true, Interval: 30, Timeout: 1200, Failures: 3}
	}
	if cfg.TrollIPv4 == nil {
		cfg.TrollIPv4 = []string{}
	}
	if cfg.TrollIPv6 == nil {
		cfg.TrollIPv6 = []string{}
	}
	if len(cfg.TrollHosts) == 0 {
		cfg.TrollHosts = []string{"4chan.org", "neopets.com", "homestarrunner.com", "theonion.com", "archive.org", "wikipedia.org"}
	}
	if strings.TrimSpace(cfg.DirectOverrideTo) == "" {
		cfg.DirectOverrideTo = cfg.PortalHost
	}
	cfg.Blocked = ensureRule(cfg.Blocked, "use-application-dns.net")
	if cfg.PortalHost == "" {
		cfg.PortalHost = "dns.leaf"
	}
	if cfg.PortalIP == "" {
		cfg.PortalIP = "127.0.0.1"
	}
	if len(cfg.Blocklists) == 0 && cfg.Blocklist != "" {
		cfg.Blocklists = append(cfg.Blocklists, BlocklistSource{Name: "Local blocklist", Source: cfg.Blocklist, Enabled: true})
	}
	if cfg.Auth.Users == nil {
		cfg.Auth.Users = []UserAuth{}
	}
	if !cfg.Auth.Enabled && len(cfg.Auth.Users) == 0 {
		cfg.Auth.Enabled = true
	}
	if err := validateConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, err
}

func NewDNSLeaf(cfg Config, cfgPath string) *DNSLeaf {
	if abs, err := filepath.Abs(cfgPath); err == nil {
		cfgPath = abs
	}
	baseDir := filepath.Dir(cfgPath)
	d := &DNSLeaf{
		cfg:                cfg,
		blocked:            make(map[string]bool),
		blockedSrc:         make(map[string]string),
		ruleCache:          make(map[string]*regexp.Regexp),
		gravityByList:      make(map[string][]uint32),
		cache:              make(map[string]cacheEntry),
		log:                make([]QueryEntry, 0, 200),
		audit:              make([]AuditEntry, 0, 200),
		clients:            make(map[string]*clientState),
		sessions:           make(map[string]Session),
		serverLog:          make([]string, 0, 200),
		seenSource:         make(map[string]bool),
		rateHits:           make(map[string][]time.Time),
		anomalyHits:        make(map[string][]time.Time),
		unhealthyUpstreams: make(map[string]bool),
		loginAttempts:      make(map[string]loginAttempt),
		stateSaveCh:        make(chan struct{}, 1),
		stateStopCh:        make(chan struct{}),
		stateDoneCh:        make(chan struct{}),
		stopCh:             make(chan struct{}),
		started:            time.Now(),
		cfgPath:            cfgPath,
		statePath:          filepath.Join(baseDir, "stats.json"),
		gravityDir:         filepath.Join(baseDir, "gravity"),
	}
	d.loadPersistentState()
	go d.persistentStateLoop()
	return d
}

func (d *DNSLeaf) runtimePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(filepath.Dir(d.cfgPath), path)
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if runtime.GOOS != "windows" {
			return err
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return err
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return err
		}
	}
	removeTemp = false
	return nil
}

func (d *DNSLeaf) saveConfig() error {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	return d.saveConfigLocked()
}

func (d *DNSLeaf) saveConfigLocked() error {
	d.configSaveMu.Lock()
	defer d.configSaveMu.Unlock()
	if err := validateConfig(d.cfg); err != nil {
		return err
	}
	data, err := json.MarshalIndent(d.cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(d.cfgPath, data, 0600)
}

func (d *DNSLeaf) setPersistenceError(err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	d.persistenceMu.Lock()
	changed := d.persistenceErr != message
	d.persistenceErr = message
	d.persistenceMu.Unlock()
	if changed && message != "" {
		d.addServerLog("persistent state error: " + message)
	}
}

func (d *DNSLeaf) persistenceError() string {
	d.persistenceMu.RLock()
	defer d.persistenceMu.RUnlock()
	return d.persistenceErr
}

func (d *DNSLeaf) trimQueryLogLocked(now time.Time) {
	if d.cfg.QueryLogRetention > 0 {
		cutoff := now.Add(-time.Duration(d.cfg.QueryLogRetention) * time.Hour).UnixMilli()
		first := 0
		for first < len(d.log) && d.log[first].Timestamp > 0 && d.log[first].Timestamp < cutoff {
			first++
		}
		if first > 0 {
			d.log = d.log[first:]
		}
	}
	if len(d.log) > 200 {
		d.log = d.log[len(d.log)-200:]
	}
}

func (d *DNSLeaf) loadPersistentState() {
	data, err := os.ReadFile(d.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			d.setPersistenceError(err)
		}
		return
	}
	var state PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		d.setPersistenceError(fmt.Errorf("decode %s: %w", d.statePath, err))
		return
	}
	d.setPersistenceError(nil)
	d.stats = state.Stats
	if len(state.Log) > 200 {
		state.Log = state.Log[len(state.Log)-200:]
	}
	d.log = state.Log
	d.logMu.Lock()
	d.trimQueryLogLocked(time.Now())
	d.logMu.Unlock()
	if len(state.Audit) > 200 {
		state.Audit = state.Audit[len(state.Audit)-200:]
	}
	d.audit = state.Audit
	if state.Clients != nil {
		d.clientsMu.Lock()
		for ip, item := range state.Clients {
			if len(d.clients) >= maxTrackedClients {
				break
			}
			lastSeen, _ := time.Parse(time.RFC3339, item.LastSeen)
			cp := clientState{
				queries:   item.Queries,
				blocked:   item.Blocked,
				local:     item.Local,
				cached:    item.Cached,
				forwarded: item.Forwarded,
				denied:    item.Denied,
				trolled:   item.Trolled,
				lastSeen:  lastSeen,
			}
			d.clients[ip] = &cp
		}
		d.clientsMu.Unlock()
	}
}

func (d *DNSLeaf) savePersistentState() error {
	d.statsMu.Lock()
	stats := d.stats
	d.statsMu.Unlock()
	d.logMu.Lock()
	logCopy := make([]QueryEntry, len(d.log))
	copy(logCopy, d.log)
	d.logMu.Unlock()
	d.auditMu.Lock()
	auditCopy := make([]AuditEntry, len(d.audit))
	copy(auditCopy, d.audit)
	d.auditMu.Unlock()
	d.clientsMu.Lock()
	clientsCopy := make(map[string]PersistentClientState, len(d.clients))
	for ip, item := range d.clients {
		if item != nil {
			lastSeen := ""
			if !item.lastSeen.IsZero() {
				lastSeen = item.lastSeen.Format(time.RFC3339)
			}
			clientsCopy[ip] = PersistentClientState{
				Queries:   item.queries,
				Blocked:   item.blocked,
				Local:     item.local,
				Cached:    item.cached,
				Forwarded: item.forwarded,
				Denied:    item.denied,
				Trolled:   item.trolled,
				LastSeen:  lastSeen,
			}
		}
	}
	d.clientsMu.Unlock()
	data, err := json.MarshalIndent(PersistentState{Stats: stats, Log: logCopy, Audit: auditCopy, Clients: clientsCopy}, "", "  ")
	if err != nil {
		d.setPersistenceError(err)
		return err
	}
	if err := atomicWriteFile(d.statePath, data, 0600); err != nil {
		d.setPersistenceError(err)
		return err
	}
	d.setPersistenceError(nil)
	return nil
}

func (d *DNSLeaf) requestPersistentSave() {
	select {
	case d.stateSaveCh <- struct{}{}:
	default:
	}
}

func (d *DNSLeaf) persistentStateLoop() {
	defer close(d.stateDoneCh)
	for {
		select {
		case <-d.stateSaveCh:
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-timer.C:
			case <-d.stateStopCh:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				_ = d.savePersistentState()
				return
			}
			drain := true
			for drain {
				select {
				case <-d.stateSaveCh:
				default:
					drain = false
				}
			}
			_ = d.savePersistentState()
		case <-d.stateStopCh:
			_ = d.savePersistentState()
			return
		}
	}
}

func (d *DNSLeaf) stopPersistentState() {
	d.stateStopOnce.Do(func() { close(d.stateStopCh) })
	<-d.stateDoneCh
}
