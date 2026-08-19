package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newTestLeaf(t *testing.T) *DNSLeaf {
	t.Helper()
	d := NewDNSLeaf(defaultConfig(), filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(d.Stop)
	return d
}

func TestAtomicWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	if err := atomicWriteFile(path, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("unexpected data %q", data)
	}
}

func TestRuntimePathUsesConfigurationDirectory(t *testing.T) {
	dir := t.TempDir()
	d := NewDNSLeaf(defaultConfig(), filepath.Join(dir, "config.json"))
	t.Cleanup(d.Stop)
	if got, want := d.runtimePath("gravity/list.txt"), filepath.Join(dir, "gravity", "list.txt"); got != want {
		t.Fatalf("runtime path = %q, want %q", got, want)
	}
	abs := filepath.Join(dir, "absolute.txt")
	if got := d.runtimePath(abs); got != abs {
		t.Fatalf("absolute runtime path = %q, want %q", got, abs)
	}
}

func TestDecrementMessageTTL(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 10}, A: netIPv4(192, 0, 2, 1)},
		&dns.CNAME{Hdr: dns.RR_Header{Ttl: 2}, Target: "example.net."},
	}
	decrementMessageTTL(msg, 3)
	if got := msg.Answer[0].Header().Ttl; got != 7 {
		t.Fatalf("A TTL = %d, want 7", got)
	}
	if got := msg.Answer[1].Header().Ttl; got != 0 {
		t.Fatalf("CNAME TTL = %d, want 0", got)
	}
}

func TestCacheReturnsAgeAdjustedCopy(t *testing.T) {
	d := newTestLeaf(t)
	key := "example.com.:1:1"
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: netIPv4(192, 0, 2, 1)}}
	d.setCache(key, msg)
	d.cacheMu.Lock()
	entry := d.cache[key]
	entry.storedAt = time.Now().Add(-4 * time.Second)
	d.cache[key] = entry
	d.cacheMu.Unlock()
	got := d.getCached(key)
	if got == nil {
		t.Fatal("expected cached response")
	}
	if ttl := got.Answer[0].Header().Ttl; ttl > 57 || ttl < 55 {
		t.Fatalf("cached TTL = %d, want approximately 56", ttl)
	}
	got.Answer[0].Header().Ttl = 1
	if original := d.cache[key].msg.Answer[0].Header().Ttl; original != 60 {
		t.Fatalf("cache entry was not copied, original TTL = %d", original)
	}
}

func TestValidateConfig(t *testing.T) {
	if err := validateConfig(defaultConfig()); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{name: "listener", change: func(cfg *Config) { cfg.Listen = "not-an-address" }},
		{name: "record", change: func(cfg *Config) { cfg.Records = []Record{{Host: "router", Type: "A", Value: "not-an-ip"}} }},
		{name: "cache", change: func(cfg *Config) { cfg.Cache = true; cfg.CacheSize = 0 }},
		{name: "upstream", change: func(cfg *Config) { cfg.Upstreams = []string{"resolver"} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultConfig()
			test.change(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}

func TestMessageCacheTTLUsesMinimumAndNegativeTTL(t *testing.T) {
	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Ttl: 60}, A: netIPv4(192, 0, 2, 1)},
		&dns.CNAME{Hdr: dns.RR_Header{Ttl: 10}, Target: "example.net."},
	}
	if got := messageCacheTTL(msg, 5*time.Minute); got != 10*time.Second {
		t.Fatalf("positive cache TTL = %s, want 10s", got)
	}
	negative := new(dns.Msg)
	negative.Rcode = dns.RcodeNameError
	negative.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Ttl: 120}, Minttl: 30}}
	if got := messageCacheTTL(negative, 5*time.Minute); got != 30*time.Second {
		t.Fatalf("negative cache TTL = %s, want 30s", got)
	}
	empty := new(dns.Msg)
	if got := messageCacheTTL(empty, 5*time.Minute); got != 0 {
		t.Fatalf("empty response cache TTL = %s, want 0", got)
	}
}

func TestCacheKeySeparatesEDNSProperties(t *testing.T) {
	plain := new(dns.Msg)
	plain.SetQuestion("example.com.", dns.TypeA)
	plainKey, ok := cacheKeyForMessage(plain)
	if !ok {
		t.Fatal("plain query was not cacheable")
	}
	withEDNS := plain.Copy()
	withEDNS.SetEdns0(1232, true)
	ednsKey, ok := cacheKeyForMessage(withEDNS)
	if !ok {
		t.Fatal("EDNS query was not cacheable")
	}
	if plainKey == ednsKey {
		t.Fatal("EDNS properties were omitted from cache key")
	}
	withOption := withEDNS.Copy()
	withOption.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_PADDING{Padding: []byte{1}}}
	if _, ok := cacheKeyForMessage(withOption); ok {
		t.Fatal("query with EDNS option was cacheable")
	}
}

func TestConfigGuardRollsBackFailedPersistence(t *testing.T) {
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "keep"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	d := NewDNSLeaf(defaultConfig(), configDir)
	t.Cleanup(d.Stop)
	before := len(d.cfg.Records)
	handler := d.configGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.cfg.Records = append(d.cfg.Records, Record{Host: "test", Type: "A", Value: "192.0.2.1", IP: "192.0.2.1"})
		writeJSON(w, map[string]bool{"ok": true})
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(`{}`))
	req.Header.Set("X-DNSLeaf-Request", "1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("failed persistence status = %d, want %d", res.Code, http.StatusInternalServerError)
	}
	if len(d.cfg.Records) != before {
		t.Fatal("configuration mutation survived failed persistence")
	}
}

func TestHTTPMutationMarkerAndPersistence(t *testing.T) {
	d := NewDNSLeaf(defaultConfig(), filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(d.Stop)
	d.cfg.Auth.Enabled = false
	mux := http.NewServeMux()
	mux.HandleFunc("/api/records", d.handleRecords)
	handler := securityHeaders(d.configGuard(d.requireAuth(mux)))
	req := httptest.NewRequest(http.MethodPost, "/api/records", strings.NewReader(`{"host":"lan","type":"A","value":"192.0.2.10"}`))
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("missing request marker status = %d, want %d", res.Code, http.StatusForbidden)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/records", strings.NewReader(`{"host":"lan","type":"A","value":"192.0.2.10"}`))
	req.Header.Set("X-DNSLeaf-Request", "1")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("marked mutation status = %d, want %d", res.Code, http.StatusOK)
	}
	if got := res.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("security header = %q, want nosniff", got)
	}
	data, err := os.ReadFile(d.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Config
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if len(persisted.Records) != len(defaultConfig().Records)+1 {
		t.Fatalf("persisted records = %d, want %d", len(persisted.Records), len(defaultConfig().Records)+1)
	}
}

func TestDoHServesLocalRecord(t *testing.T) {
	d := newTestLeaf(t)
	d.cfg.Auth.Enabled = false
	d.cfg.LANOnly = false
	d.cfg.Records = append(d.cfg.Records, Record{Host: "lan", Type: "A", Value: "192.0.2.11", IP: "192.0.2.11"})
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", d.handleDoH)
	handler := securityHeaders(d.configGuard(d.requireAuth(mux)))
	query := new(dns.Msg)
	query.SetQuestion("lan.", dns.TypeA)
	wire, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(string(wire)))
	req.RemoteAddr = "127.0.0.1:53000"
	req.Header.Set("Content-Type", "application/dns-message")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("DoH status = %d, want %d", res.Code, http.StatusOK)
	}
	response := new(dns.Msg)
	if err := response.Unpack(res.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.0.2.11" {
		t.Fatalf("unexpected DoH answer %#v", response.Answer)
	}
}

func TestHealthAndReadinessEndpoints(t *testing.T) {
	d := newTestLeaf(t)
	res := httptest.NewRecorder()
	d.handleHealthz(res, httptest.NewRequest(http.MethodGet, "/api/healthz", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("health status = %d, want %d", res.Code, http.StatusOK)
	}
	res = httptest.NewRecorder()
	d.handleReadyz(res, httptest.NewRequest(http.MethodGet, "/api/readyz", nil))
	if res.Code != http.StatusServiceUnavailable {
		t.Fatalf("readiness status = %d, want %d before start", res.Code, http.StatusServiceUnavailable)
	}
}

func TestConfigSchemaMigration(t *testing.T) {
	cfg := defaultConfig()
	cfg.SchemaVersion = 0
	if err := migrateConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != currentConfigSchema {
		t.Fatalf("migrated schema = %d, want %d", cfg.SchemaVersion, currentConfigSchema)
	}
	cfg.SchemaVersion = currentConfigSchema + 1
	if err := migrateConfig(&cfg); err == nil {
		t.Fatal("future schema was accepted")
	}
}

func TestRuntimeStateMapsAreBounded(t *testing.T) {
	d := newTestLeaf(t)
	for i := 0; i < maxTrackedClients+1; i++ {
		d.trackClient("client-"+strconv.Itoa(i), "forwarded")
	}
	d.clientsMu.Lock()
	clients := len(d.clients)
	d.clientsMu.Unlock()
	if clients > maxTrackedClients {
		t.Fatalf("tracked clients = %d, max %d", clients, maxTrackedClients)
	}
	for i := 0; i < maxLoginEntries+1; i++ {
		d.noteLoginFailure("login-" + strconv.Itoa(i))
	}
	d.loginMu.Lock()
	logins := len(d.loginAttempts)
	d.loginMu.Unlock()
	if logins > maxLoginEntries {
		t.Fatalf("login attempts = %d, max %d", logins, maxLoginEntries)
	}
}

func FuzzParseBlocklistLine(f *testing.F) {
	for _, seed := range []string{"example.com", "0.0.0.0 example.com", "! comment", "*.example.com", "^ads\\.example\\.com$"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_ = parseBlocklistLine(line)
	})
}

func TestValidUsername(t *testing.T) {
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{name: "admin", valid: true},
		{name: "ops@example.net", valid: true},
		{name: "bad user", valid: false},
		{name: "", valid: false},
		{name: strings.Repeat("a", 65), valid: false},
	} {
		if got := validUsername(test.name); got != test.valid {
			t.Errorf("validUsername(%q) = %t, want %t", test.name, got, test.valid)
		}
	}
}

func TestUserChangesProtectLastAdminAndRevokeSessions(t *testing.T) {
	d := newTestLeaf(t)
	d.cfg.Auth.Enabled = true
	d.cfg.Auth.Users = []UserAuth{
		{Username: "admin", PasswordHash: passwordHash("old"), Role: "admin"},
		{Username: "viewer", PasswordHash: passwordHash("viewer"), Role: "viewer"},
	}
	d.sessions["admin-session"] = Session{Username: "admin", Role: "admin", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodPatch, "/api/users", strings.NewReader(`{"username":"admin","role":"viewer"}`))
	res := httptest.NewRecorder()
	d.handleUsers(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("last-admin demotion status = %d, want %d", res.Code, http.StatusBadRequest)
	}
	if d.cfg.Auth.Users[0].Role != "admin" {
		t.Fatal("last administrator was demoted")
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/users", strings.NewReader(`{"username":"admin","password":"new-password"}`))
	res = httptest.NewRecorder()
	d.handleUsers(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("password update status = %d, want %d", res.Code, http.StatusOK)
	}
	if _, ok := d.sessions["admin-session"]; ok {
		t.Fatal("administrator session survived password change")
	}
	if !verifyPassword("new-password", d.cfg.Auth.Users[0].PasswordHash) {
		t.Fatal("new password does not verify")
	}
}

func netIPv4(a, b, c, d byte) net.IP {
	return net.IPv4(a, b, c, d)
}
