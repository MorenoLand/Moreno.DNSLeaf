package main

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gdamore/tcell/v3"
	"github.com/miekg/dns"
	"github.com/x0rbyte/tview"
)

//go:embed dnsleaf.png
var logoPNG []byte

var proxyTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

type Record struct {
	Host     string `json:"host"`
	Type     string `json:"type,omitempty"`
	Value    string `json:"value,omitempty"`
	IP       string `json:"ip,omitempty"`
	Note     string `json:"note,omitempty"`
	Priority uint16 `json:"priority,omitempty"`
	Weight   uint16 `json:"weight,omitempty"`
	Port     uint16 `json:"port,omitempty"`
}

type BlockedEntry struct {
	Domain string `json:"domain"`
	Source string `json:"source"`
}

type BlocklistSource struct {
	Name          string   `json:"name"`
	Source        string   `json:"source"`
	Enabled       bool     `json:"enabled"`
	Allowlist     []string `json:"allowlist,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	LastLoaded    int      `json:"last_loaded"`
	LastError     string   `json:"last_error,omitempty"`
	LastChecked   string   `json:"last_checked,omitempty"`
	LastRefreshed string   `json:"last_refreshed,omitempty"`
	CacheAge      int64    `json:"cache_age_seconds,omitempty"`
}

type UpstreamEndpoint struct {
	URL        string `json:"url"`
	ServerName string `json:"server_name,omitempty"`
}

type BlockGroup struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
	Sources []string `json:"sources,omitempty"`
}

type GravityProgress struct {
	Running bool     `json:"running"`
	Target  string   `json:"target"`
	Started string   `json:"started,omitempty"`
	Ended   string   `json:"ended,omitempty"`
	Error   string   `json:"error,omitempty"`
	Lines   []string `json:"lines"`
}

type QueryEntry struct {
	Timestamp   int64  `json:"ts,omitempty"`
	Time        string `json:"time"`
	Client      string `json:"client"`
	ClientIP    string `json:"client_ip"`
	ClientName  string `json:"client_name,omitempty"`
	ClientMAC   string `json:"client_mac,omitempty"`
	MACStatus   string `json:"mac_status,omitempty"`
	LocalAddr   string `json:"local_addr,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Domain      string `json:"domain"`
	Answers     string `json:"answers,omitempty"`
	Type        string `json:"type"`
	Action      string `json:"action"`
	BlockSource string `json:"block_source,omitempty"`
	Duration    int64  `json:"duration_ms"`
}

type AuditEntry struct {
	Timestamp int64  `json:"ts"`
	Time      string `json:"time"`
	Username  string `json:"username"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
}

type ClientProfile struct {
	Disabled        bool     `json:"disabled,omitempty"`
	DisableBlocking bool     `json:"disable_blocking,omitempty"`
	SafeSearch      bool     `json:"safe_search,omitempty"`
	Blocklists      []string `json:"blocklists,omitempty"`
	Blocked         []string `json:"blocked"`
	Allowed         []string `json:"allowed"`
}

type ScheduledRule struct {
	Domain  string   `json:"domain"`
	Action  string   `json:"action"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	Days    []string `json:"days,omitempty"`
	Enabled bool     `json:"enabled"`
}

type RateLimitConfig struct {
	Enabled bool   `json:"enabled"`
	Queries int    `json:"queries"`
	Window  int    `json:"window_seconds"`
	Action  string `json:"action"`
}

type AnomalyConfig struct {
	Enabled bool `json:"enabled"`
	Hits    int  `json:"hits"`
	Window  int  `json:"window_seconds"`
}

type ConditionalForward struct {
	Suffix    string   `json:"suffix"`
	Upstreams []string `json:"upstreams"`
	Enabled   bool     `json:"enabled"`
}

type UpstreamHealthConfig struct {
	Enabled  bool `json:"enabled"`
	Interval int  `json:"interval_seconds"`
	Timeout  int  `json:"timeout_ms"`
	Failures int  `json:"failures"`
}

type PersistentState struct {
	Stats   Stats                            `json:"stats"`
	Log     []QueryEntry                     `json:"log"`
	Audit   []AuditEntry                     `json:"audit"`
	Clients map[string]PersistentClientState `json:"clients"`
}

type PersistentClientState struct {
	Queries   int64  `json:"queries"`
	Blocked   int64  `json:"blocked"`
	Local     int64  `json:"local"`
	Cached    int64  `json:"cached"`
	Forwarded int64  `json:"forwarded"`
	Denied    int64  `json:"denied"`
	Trolled   int64  `json:"trolled"`
	LastSeen  string `json:"last_seen"`
}

type Stats struct {
	Queries   int64 `json:"total_queries"`
	Blocked   int64 `json:"blocked"`
	Local     int64 `json:"local"`
	Cached    int64 `json:"cached"`
	Forwarded int64 `json:"forwarded"`
}

type Config struct {
	SchemaVersion      int                      `json:"schema_version"`
	Listen             string                   `json:"listen"`
	HTTP               string                   `json:"http"`
	HTTPS              string                   `json:"https"`
	TLSCert            string                   `json:"tls_cert_file"`
	TLSKey             string                   `json:"tls_key_file"`
	Upstreams          []string                 `json:"upstreams"`
	DisabledUpstreams  []string                 `json:"disabled_upstreams"`
	Records            []Record                 `json:"records"`
	Blocked            []string                 `json:"blocked"`
	BlockedIPs         []string                 `json:"blocked_ips"`
	Allowed            []string                 `json:"allowed"`
	Blocklist          string                   `json:"blocklist_file"`
	Blocklists         []BlocklistSource        `json:"blocklists"`
	UpstreamEndpoints  []UpstreamEndpoint       `json:"upstream_endpoints,omitempty"`
	BlockGroups        []BlockGroup             `json:"block_groups"`
	Cache              bool                     `json:"cache_enabled"`
	CacheSize          int                      `json:"cache_size"`
	CacheTTL           int                      `json:"cache_ttl_seconds"`
	StripECS           bool                     `json:"strip_ecs"`
	QueryLogEnabled    bool                     `json:"query_log_enabled"`
	QueryLogRetention  int                      `json:"query_log_retention_hours"`
	AnonymizeClientIPs bool                     `json:"anonymize_client_ips"`
	PortalHost         string                   `json:"portal_host"`
	PortalIP           string                   `json:"portal_ip"`
	LANOnly            bool                     `json:"lan_only"`
	WhitelistOnly      bool                     `json:"whitelist_only"`
	Whitelist          []string                 `json:"whitelist"`
	ResolverDisabled   bool                     `json:"resolver_disabled"`
	ClientNames        map[string]string        `json:"client_names"`
	ClientProfiles     map[string]string        `json:"client_profiles"`
	DefaultProfile     string                   `json:"default_profile"`
	Profiles           map[string]ClientProfile `json:"profiles"`
	ScheduledRules     []ScheduledRule          `json:"scheduled_rules"`
	DoT                string                   `json:"dot"`
	RateLimit          RateLimitConfig          `json:"rate_limit"`
	Anomaly            AnomalyConfig            `json:"anomaly"`
	ConditionalForward []ConditionalForward     `json:"conditional_forwarding"`
	DHCPLeasesFile     string                   `json:"dhcp_leases_file"`
	UpstreamHealth     UpstreamHealthConfig     `json:"upstream_health"`
	DirectOverride     bool                     `json:"direct_override"`
	DirectOverrideTo   string                   `json:"direct_override_to"`
	TrollMode          bool                     `json:"troll_mode"`
	TrollHosts         []string                 `json:"troll_hosts"`
	TrollIPv4          []string                 `json:"troll_ipv4"`
	TrollIPv6          []string                 `json:"troll_ipv6"`
	HTTPProxyEnabled   bool                     `json:"http_proxy_enabled"`
	HTTPProxy          string                   `json:"http_proxy"`
	SOCKSProxyEnabled  bool                     `json:"socks_proxy_enabled"`
	SOCKSProxy         string                   `json:"socks_proxy"`
	Auth               AuthConfig               `json:"auth"`
}

type AuthConfig struct {
	Enabled bool       `json:"enabled"`
	Users   []UserAuth `json:"users"`
}

type UserAuth struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	CreatedAt    string `json:"created_at"`
}

type ClientInfo struct {
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Profile     string `json:"profile,omitempty"`
	Allowed     bool   `json:"allowed"`
	Whitelisted bool   `json:"whitelisted"`
	LAN         bool   `json:"lan"`
	Queries     int64  `json:"queries"`
	Blocked     int64  `json:"blocked"`
	Local       int64  `json:"local"`
	Cached      int64  `json:"cached"`
	Forwarded   int64  `json:"forwarded"`
	Denied      int64  `json:"denied"`
	Trolled     int64  `json:"trolled"`
	LastSeen    string `json:"last_seen"`
}

type clientState struct {
	queries   int64
	blocked   int64
	local     int64
	cached    int64
	forwarded int64
	denied    int64
	trolled   int64
	lastSeen  time.Time
}

type loginAttempt struct {
	Failures    int
	FirstFailed time.Time
	BlockedTill time.Time
}

type cacheEntry struct {
	msg       *dns.Msg
	storedAt  time.Time
	expiresAt time.Time
}

type DNSLeaf struct {
	cfg                Config
	cfgMu              sync.RWMutex
	configSaveMu       sync.Mutex
	blocked            map[string]bool
	blockedSrc         map[string]string
	blockedPat         []string
	ruleCacheMu        sync.RWMutex
	ruleCache          map[string]*regexp.Regexp
	gravity            []string
	gravityByList      map[string][]uint32
	blockMu            sync.RWMutex
	cache              map[string]cacheEntry
	cacheMu            sync.RWMutex
	stats              Stats
	statsMu            sync.Mutex
	log                []QueryEntry
	logMu              sync.Mutex
	audit              []AuditEntry
	auditMu            sync.Mutex
	clients            map[string]*clientState
	clientsMu          sync.Mutex
	sessions           map[string]Session
	sessMu             sync.Mutex
	serverLog          []string
	serverMu           sync.Mutex
	seenSource         map[string]bool
	seenMu             sync.Mutex
	rateMu             sync.Mutex
	rateHits           map[string][]time.Time
	anomalyMu          sync.Mutex
	anomalyHits        map[string][]time.Time
	healthMu           sync.RWMutex
	unhealthyUpstreams map[string]bool
	gravityMu          sync.Mutex
	gravityProgress    GravityProgress
	loginMu            sync.Mutex
	loginAttempts      map[string]loginAttempt
	stateSaveCh        chan struct{}
	stateStopCh        chan struct{}
	stateDoneCh        chan struct{}
	stateStopOnce      sync.Once
	persistenceMu      sync.RWMutex
	persistenceErr     string
	stopCh             chan struct{}
	stopMu             sync.Mutex
	stopOnce           sync.Once
	stopped            bool
	dnsServers         []*dns.Server
	httpServers        []*http.Server
	proxyListeners     []net.Listener
	httpListeners      []net.Listener
	serversMu          sync.Mutex
	readyMu            sync.RWMutex
	dnsReady           int
	httpReady          int
	startupErr         string
	ui                 *consoleUI
	started            time.Time
	cfgPath            string
	statePath          string
	gravityDir         string
}

type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

const consoleSidebarWidth = 34
const consoleInputHeight = 3
const currentConfigSchema = 1

type consoleUI struct {
	app       *tview.Application
	screen    tcell.Screen
	sidebar   *tview.TextView
	log       *tview.TextView
	input     *tview.InputField
	logStyle  tcell.Style
	dad       *DNSLeaf
	mu        sync.Mutex
	lines     []string
	running   bool
	inCommand bool
}

type remoteConsole struct {
	app     *tview.Application
	sidebar *tview.TextView
	log     *tview.TextView
	input   *tview.InputField
	base    string
	client  *http.Client
	lines   []string
	mu      sync.Mutex
}

//go:embed web/index.html
var indexHTML string

func (d *DNSLeaf) consoleLogf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	d.addServerLog(msg)
	if d.ui != nil {
		d.ui.appendLog(msg)
		return
	}
	fmt.Println(msg)
}

func (d *DNSLeaf) addServerLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	d.serverMu.Lock()
	defer d.serverMu.Unlock()
	d.serverLog = append(d.serverLog, time.Now().Format("15:04:05")+"  "+line)
	if len(d.serverLog) > 300 {
		d.serverLog = d.serverLog[len(d.serverLog)-300:]
	}
}

func (d *DNSLeaf) gravityLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	d.gravityMu.Lock()
	d.gravityProgress.Lines = append(d.gravityProgress.Lines, time.Now().Format("15:04:05")+"  "+line)
	if len(d.gravityProgress.Lines) > 500 {
		d.gravityProgress.Lines = d.gravityProgress.Lines[len(d.gravityProgress.Lines)-500:]
	}
	d.gravityMu.Unlock()
}

func (d *DNSLeaf) gravitySnapshot() GravityProgress {
	d.gravityMu.Lock()
	defer d.gravityMu.Unlock()
	p := d.gravityProgress
	p.Lines = append([]string(nil), d.gravityProgress.Lines...)
	return p
}

func (d *DNSLeaf) startGravity(target string) error {
	target = strings.TrimSpace(target)
	d.gravityMu.Lock()
	if d.gravityProgress.Running {
		d.gravityMu.Unlock()
		return fmt.Errorf("gravity update already running")
	}
	label := target
	if label == "" {
		label = "all lists"
	}
	d.gravityProgress = GravityProgress{Running: true, Target: label, Started: time.Now().Format(time.RFC3339), Lines: []string{time.Now().Format("15:04:05") + "  starting gravity update: " + label}}
	d.gravityMu.Unlock()
	go func() {
		d.cfgMu.Lock()
		err := d.refreshBlocklistTarget(target)
		if err == nil {
			err = d.saveConfigLocked()
		}
		d.cfgMu.Unlock()
		d.gravityMu.Lock()
		d.gravityProgress.Running = false
		d.gravityProgress.Ended = time.Now().Format(time.RFC3339)
		if err != nil {
			d.gravityProgress.Error = err.Error()
			d.gravityProgress.Lines = append(d.gravityProgress.Lines, time.Now().Format("15:04:05")+"  failed: "+err.Error())
		} else {
			d.blockMu.RLock()
			count := d.blockedCountLocked()
			d.blockMu.RUnlock()
			d.gravityProgress.Lines = append(d.gravityProgress.Lines, fmt.Sprintf("%s  complete: %d domains active", time.Now().Format("15:04:05"), count))
		}
		d.gravityMu.Unlock()
	}()
	return nil
}

type serverLogWriter struct{ dad *DNSLeaf }

func (w serverLogWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !isNoisyTLSEOF(line) {
			w.dad.addServerLog(line)
		}
	}
	return len(p), nil
}

func isNoisyTLSEOF(line string) bool {
	return strings.Contains(line, "TLS handshake error") && strings.HasSuffix(line, ": EOF")
}

func (d *DNSLeaf) addLog(client, localAddr, transport, domain, qtype, action, answers string, dur time.Duration, blockSource ...string) {
	ip := normalizeClientIP(client)
	if !d.cfg.QueryLogEnabled {
		return
	}
	loggedIP := ip
	loggedClient := client
	loggedLocalAddr := localAddr
	name := ""
	mac := ""
	macStatus := ""
	if !d.cfg.AnonymizeClientIPs {
		name = d.clientName(ip)
		mac, macStatus = lookupClientMAC(ip)
	}
	if d.cfg.AnonymizeClientIPs {
		loggedIP = anonymizeClientIP(ip)
		loggedClient = loggedIP
		loggedLocalAddr = ""
		name = ""
		mac = ""
		macStatus = ""
	}
	d.noteSource(loggedIP, loggedClient, loggedLocalAddr, transport, mac, macStatus)
	now := time.Now()
	source := ""
	if len(blockSource) > 0 {
		source = blockSource[0]
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	d.log = append(d.log, QueryEntry{
		Timestamp:   now.UnixMilli(),
		Time:        now.Format("15:04:05"),
		Client:      loggedClient,
		ClientIP:    loggedIP,
		ClientName:  name,
		ClientMAC:   mac,
		MACStatus:   macStatus,
		LocalAddr:   loggedLocalAddr,
		Transport:   transport,
		Domain:      domain,
		Answers:     answers,
		Type:        qtype,
		Action:      action,
		BlockSource: source,
		Duration:    dur.Milliseconds(),
	})
	d.trimQueryLogLocked(now)
	d.requestPersistentSave()
}

func (d *DNSLeaf) addAudit(r *http.Request, status int) {
	if r == nil || !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/login" || r.URL.Path == "/api/session" {
		return
	}
	username := "anonymous"
	if session, ok := d.sessionFromRequest(r); ok {
		username = session.Username
	}
	now := time.Now()
	d.auditMu.Lock()
	d.audit = append(d.audit, AuditEntry{Timestamp: now.UnixMilli(), Time: now.Format(time.RFC3339), Username: username, Method: r.Method, Path: r.URL.Path, Status: status})
	if len(d.audit) > 200 {
		d.audit = d.audit[len(d.audit)-200:]
	}
	d.auditMu.Unlock()
	d.requestPersistentSave()
}

func (d *DNSLeaf) noteSource(ip, remote, localAddr, transport, mac, macStatus string) {
	key := transport + "|" + ip + "|" + localAddr
	d.seenMu.Lock()
	if d.seenSource[key] {
		d.seenMu.Unlock()
		return
	}
	if len(d.seenSource) >= maxSeenSources {
		for existing := range d.seenSource {
			delete(d.seenSource, existing)
			break
		}
	}
	d.seenSource[key] = true
	d.seenMu.Unlock()
	if mac == "" {
		mac = "-"
	}
	d.addServerLog(fmt.Sprintf("first DNS source transport=%s remote=%s ip=%s local=%s mac=%s mac_status=%s", transport, remote, ip, localAddr, mac, macStatus))
}

func (d *DNSLeaf) addStat(key string) {
	d.statsMu.Lock()
	defer d.statsMu.Unlock()
	d.stats.Queries++
	switch key {
	case "blocked":
		d.stats.Blocked++
	case "local":
		d.stats.Local++
	case "cached":
		d.stats.Cached++
	case "forwarded":
		d.stats.Forwarded++
	}
}

func processMemory() string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return fmt.Sprintf("%.1f MB", float64(mem.Alloc)/1024/1024)
}

func processCPUPercent() string {
	seconds, ok := processCPUSeconds()
	if !ok {
		return "n/a"
	}
	now := time.Now()
	processCPUSample.Lock()
	defer processCPUSample.Unlock()
	if !processCPUSample.seen {
		processCPUSample.cpuSeconds = seconds
		processCPUSample.wall = now
		processCPUSample.seen = true
		return "sampling"
	}
	wall := now.Sub(processCPUSample.wall).Seconds()
	cpu := seconds - processCPUSample.cpuSeconds
	processCPUSample.cpuSeconds = seconds
	processCPUSample.wall = now
	if wall <= 0 || cpu < 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", cpu/wall*100)
}

func processCPUSeconds() (float64, bool) {
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			return 0, false
		}
		text := string(raw)
		idx := strings.LastIndex(text, ") ")
		if idx < 0 || idx+2 >= len(text) {
			return 0, false
		}
		fields := strings.Fields(text[idx+2:])
		if len(fields) < 13 {
			return 0, false
		}
		utime, err1 := strconv.ParseFloat(fields[11], 64)
		stime, err2 := strconv.ParseFloat(fields[12], 64)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return (utime + stime) / 100.0, true
	case "windows":
		ps := fmt.Sprintf("(Get-Process -Id %d).CPU", os.Getpid())
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
		if err != nil {
			return 0, false
		}
		seconds, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		return seconds, err == nil
	default:
		return 0, false
	}
}

func linuxTemp() string {
	matches, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		if v > 1000 {
			v = v / 1000
		}
		if v > 0 {
			return fmt.Sprintf("%.1f C", v)
		}
	}
	return "n/a"
}

func linuxCPUPercent() string {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return "n/a"
	}
	fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return "n/a"
	}
	vals := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return "n/a"
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuPercentFromSample(total, idle)
}

func linuxMemory() string {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "n/a"
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] = v
		}
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total == 0 || available == 0 {
		return "n/a"
	}
	used := total - available
	return fmt.Sprintf("%.1f / %.1f GB", float64(used)/1024/1024, float64(total)/1024/1024)
}

func windowsCPUPercent() string {
	out, err := exec.Command("typeperf", `\Processor(_Total)\% Processor Time`, "-sc", "1").Output()
	if err != nil {
		return "n/a"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, `"(`) || !strings.Contains(line, ",") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		v := strings.Trim(parts[len(parts)-1], `" `)
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return fmt.Sprintf("%.1f%%", f)
		}
	}
	return "n/a"
}

func windowsMemory() string {
	ps := `Add-Type -AssemblyName Microsoft.VisualBasic; $c=New-Object Microsoft.VisualBasic.Devices.ComputerInfo; "$($c.TotalPhysicalMemory),$($c.AvailablePhysicalMemory)"`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return "n/a"
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(parts) < 2 {
		return "n/a"
	}
	total, _ := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
	free, _ := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
	if total == 0 {
		return "n/a"
	}
	used := total - free
	return fmt.Sprintf("%.1f / %.1f GB", float64(used)/1024/1024/1024, float64(total)/1024/1024/1024)
}

func windowsTemp() string {
	ps := `try { Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1 -ExpandProperty CurrentTemperature } catch { "" }`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return "n/a"
	}
	raw, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil || raw <= 0 {
		return "n/a"
	}
	c := raw/10 - 273.15
	if c > -50 && c < 150 {
		return fmt.Sprintf("%.1f C", c)
	}
	return "n/a"
}

func cpuPercentFromSample(total, idle uint64) string {
	cpuSample.Lock()
	defer cpuSample.Unlock()
	if !cpuSample.seen {
		cpuSample.total, cpuSample.idle, cpuSample.seen = total, idle, true
		return "sampling"
	}
	dTotal := total - cpuSample.total
	dIdle := idle - cpuSample.idle
	cpuSample.total, cpuSample.idle = total, idle
	if dTotal == 0 {
		return "0.0%"
	}
	used := float64(dTotal-dIdle) / float64(dTotal) * 100
	return fmt.Sprintf("%.1f%%", used)
}

func (d *DNSLeaf) handleCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "validate" || args[0] == "check-config" {
		d.cfgMu.RLock()
		err := validateConfig(d.cfg)
		schema := d.cfg.SchemaVersion
		d.cfgMu.RUnlock()
		if err != nil {
			fmt.Printf("configuration invalid: %v\n", err)
		} else {
			fmt.Printf("configuration valid (schema %d)\n", schema)
		}
		return true
	}
	if args[0] == "service" {
		return d.handleServiceCLI(args[1:])
	}
	if args[0] != "user" {
		return false
	}
	if len(args) < 2 {
		fmt.Println("usage: dnsleaf user list | add <username> <password> [admin|viewer] | reset <username> <password> | role <username> <admin|viewer> | remove <username>")
		return true
	}
	switch args[1] {
	case "list":
		if len(d.cfg.Auth.Users) == 0 {
			fmt.Println("no users configured")
			return true
		}
		for _, user := range d.cfg.Auth.Users {
			fmt.Printf("%s\t%s\t%s\n", user.Username, user.Role, user.CreatedAt)
		}
	case "add":
		if len(args) < 4 {
			fmt.Println("usage: dnsleaf user add <username> <password> [admin|viewer]")
			return true
		}
		role := "viewer"
		if len(args) >= 5 {
			role = args[4]
		}
		if role != "admin" && role != "viewer" {
			fmt.Println("role must be admin or viewer")
			return true
		}
		if !validUsername(args[2]) || args[3] == "" || len(args[3]) > 4096 {
			fmt.Println("username and password are invalid")
			return true
		}
		if _, ok := d.findUser(args[2]); ok {
			fmt.Println("user already exists")
			return true
		}
		d.cfg.Auth.Enabled = true
		d.cfg.Auth.Users = append(d.cfg.Auth.Users, UserAuth{Username: args[2], PasswordHash: passwordHash(args[3]), Role: role, CreatedAt: time.Now().Format(time.RFC3339)})
		if err := d.saveConfig(); err != nil {
			fmt.Printf("save failed: %v\n", err)
			return true
		}
		fmt.Printf("added %s as %s\n", args[2], role)
	case "reset":
		if len(args) < 4 {
			fmt.Println("usage: dnsleaf user reset <username> <password>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				d.cfg.Auth.Users[i].PasswordHash = passwordHash(args[3])
				if err := d.saveConfig(); err != nil {
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("reset password for %s\n", args[2])
				return true
			}
		}
		fmt.Println("user not found")
	case "role":
		if len(args) < 4 || (args[3] != "admin" && args[3] != "viewer") {
			fmt.Println("usage: dnsleaf user role <username> <admin|viewer>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				if user.Role == "admin" && args[3] != "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot demote the last administrator")
					return true
				}
				d.cfg.Auth.Users[i].Role = args[3]
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users[i] = user
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("updated %s to %s\n", args[2], args[3])
				return true
			}
		}
		fmt.Println("user not found")
	case "remove":
		if len(args) < 3 {
			fmt.Println("usage: dnsleaf user remove <username>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				if len(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot remove the last user")
					return true
				}
				if user.Role == "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot remove the last administrator")
					return true
				}
				users := append([]UserAuth(nil), d.cfg.Auth.Users...)
				d.cfg.Auth.Users = append(d.cfg.Auth.Users[:i], d.cfg.Auth.Users[i+1:]...)
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users = users
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("removed %s\n", args[2])
				return true
			}
		}
		fmt.Println("user not found")
	default:
		fmt.Println("unknown user command")
	}
	return true
}

func (d *DNSLeaf) handleServiceCLI(args []string) bool {
	if len(args) == 0 {
		fmt.Println("usage: dnsleaf service install | uninstall")
		return true
	}
	switch args[0] {
	case "install":
		if err := d.installLinuxService(); err != nil {
			fmt.Fprintf(os.Stderr, "service install failed: %v\n", err)
			return true
		}
		fmt.Println("installed dnsleaf.service")
		fmt.Println("start with: sudo systemctl enable --now dnsleaf")
	case "uninstall", "remove":
		if err := d.uninstallLinuxService(); err != nil {
			fmt.Fprintf(os.Stderr, "service uninstall failed: %v\n", err)
			return true
		}
		fmt.Println("removed dnsleaf.service")
	default:
		fmt.Println("usage: dnsleaf service install | uninstall")
	}
	return true
}

func (d *DNSLeaf) installLinuxService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd service install is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo ./dnsleaf service install")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	cfgPath, err := filepath.Abs(d.cfgPath)
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=DNSLeaf DNS resolver and admin panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s --no-tui --config %s
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, systemdEscape(filepath.Dir(cfgPath)), systemdEscape(exe), systemdEscape(cfgPath))
	if err := os.WriteFile("/etc/systemd/system/dnsleaf.service", []byte(unit), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func (d *DNSLeaf) uninstallLinuxService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd service uninstall is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo ./dnsleaf service uninstall")
	}
	_ = exec.Command("systemctl", "disable", "--now", "dnsleaf").Run()
	if err := os.Remove("/etc/systemd/system/dnsleaf.service"); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "reset-failed", "dnsleaf").Run()
	return nil
}

func systemdEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, " ", `\x20`, "\t", `\x09`, "\n", "")
	return replacer.Replace(value)
}

func newConsoleUI(dad *DNSLeaf) (*consoleUI, error) {
	screen, err := tcell.NewScreen()
	if err != nil {
		return nil, err
	}
	if err := screen.Init(); err != nil {
		return nil, err
	}

	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)

	sidebar := tview.NewTextView().
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(true).
		SetTextStyle(textStyle)
	sidebar.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetBorderPadding(0, 0, 1, 1).
		SetTitle(" DNSLeaf ").
		SetTitleStyle(titleStyle)

	logView := tview.NewTextView().
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(false).
		SetTextStyle(textStyle)
	logView.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetTitle(" Console ").
		SetTitleStyle(titleStyle)

	input := tview.NewInputField().
		SetLabel("> ").
		SetLabelStyle(textStyle).
		SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).
		SetPlaceholder("Type a command...").
		SetPlaceholderStyle(tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen))
	input.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetBorderPadding(0, 0, 1, 1)

	ui := &consoleUI{
		screen:   screen,
		sidebar:  sidebar,
		log:      logView,
		input:    input,
		logStyle: textStyle,
		dad:      dad,
		lines:    []string{"dnsleaf ready. Type 'help'."},
	}

	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		command := strings.TrimSpace(ui.input.GetText())
		ui.input.SetText("")
		if command == "" {
			ui.wake()
			return
		}
		ui.runCommand(command)
	})

	body := tview.NewFlex().
		AddItem(sidebar, consoleSidebarWidth, 0, false).
		AddItem(logView, 0, 1, false)

	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, false).
		AddItem(input, consoleInputHeight, 0, true)

	ui.app = tview.NewApplication()
	ui.app.SetScreen(screen)
	ui.app.SetRoot(root)
	ui.refreshSidebar()
	ui.refreshLog()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if dad.ui != ui {
				return
			}
			ui.app.QueueUpdateDraw(func() {
				ui.refreshSidebar()
			})
		}
	}()

	return ui, nil
}

func dnsleafPingURL(cfg Config) string {
	base := webURL(cfg.HTTP)
	return strings.TrimRight(base, "/") + "/api/ping"
}

func runningDNSLeaf(cfg Config) bool {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(dnsleafPingURL(cfg))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		App string `json:"app"`
		OK  bool   `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK && body.App == "dnsleaf" && body.OK
}

func runRemoteConsole(cfg Config) error {
	return runRemoteConsoleBase(webURL(cfg.HTTP))
}

func runRemoteConsoleBase(base string) error {
	jar, _ := cookiejar.New(nil)
	base = normalizeRemoteBase(base)
	rc := &remoteConsole{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: 10 * time.Second, Jar: jar},
		lines:  []string{"connected to running DNSLeaf at " + base, "type 'login <user> <pass>', 'status', 'reload', 'blocklists', 'upstreams', or 'quit'."},
	}
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)
	rc.sidebar = tview.NewTextView().SetScrollable(true).SetWrap(true).SetWordWrap(true).SetTextStyle(textStyle)
	rc.sidebar.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(0, 0, 1, 1).SetTitle(" DNSLeaf ").SetTitleStyle(titleStyle)
	rc.log = tview.NewTextView().SetScrollable(true).SetWrap(true).SetWordWrap(false).SetTextStyle(textStyle)
	rc.log.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetTitle(" DNSLeaf Remote ").SetTitleStyle(titleStyle)
	rc.input = tview.NewInputField().SetLabel("> ").SetLabelStyle(textStyle).SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).SetPlaceholder("Type a remote command...").SetPlaceholderStyle(tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen))
	rc.input.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(0, 0, 1, 1)
	rc.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		cmd := strings.TrimSpace(rc.input.GetText())
		rc.input.SetText("")
		if cmd != "" {
			rc.run(cmd)
		}
	})
	body := tview.NewFlex().AddItem(rc.sidebar, consoleSidebarWidth, 0, false).AddItem(rc.log, 0, 1, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(body, 0, 1, false).AddItem(rc.input, consoleInputHeight, 0, true)
	rc.app = tview.NewApplication()
	rc.app.SetRoot(root)
	rc.refreshSidebar()
	rc.refresh()
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if rc.app == nil {
				return
			}
			rc.app.QueueUpdateDraw(func() {
				rc.refreshSidebar()
			})
		}
	}()
	return rc.app.Run()
}

func normalizeRemoteBase(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return "http://127.0.0.1:8080"
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}
	return strings.TrimRight(server, "/")
}

func promptRemoteServer(defaultServer string) (string, error) {
	var chosen string
	app := tview.NewApplication()
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)
	input := tview.NewInputField().
		SetLabel("Server: ").
		SetText(defaultServer).
		SetLabelStyle(textStyle).
		SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).
		SetPlaceholder("http://host:8080")
	input.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(1, 1, 2, 2).SetTitle(" DNSLeaf Remote ").SetTitleStyle(titleStyle)
	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			app.Stop()
			return
		}
		if key == tcell.KeyEnter {
			chosen = strings.TrimSpace(input.GetText())
			app.Stop()
		}
	})
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().AddItem(nil, 0, 1, false).AddItem(input, 72, 0, true).AddItem(nil, 0, 1, false), 5, 0, true).
		AddItem(nil, 0, 1, false)
	app.SetRoot(root)
	if err := app.Run(); err != nil {
		return "", err
	}
	if chosen == "" {
		return "", fmt.Errorf("remote server not selected")
	}
	return normalizeRemoteBase(chosen), nil
}

func (rc *remoteConsole) append(line string) {
	rc.mu.Lock()
	rc.lines = append(rc.lines, line)
	if len(rc.lines) > 1000 {
		rc.lines = rc.lines[len(rc.lines)-1000:]
	}
	rc.mu.Unlock()
	rc.refresh()
}

func (rc *remoteConsole) refresh() {
	rc.mu.Lock()
	text := strings.Join(rc.lines, "\n")
	rc.mu.Unlock()
	rc.log.SetText(text)
	rc.log.ScrollToEnd()
}

func (rc *remoteConsole) refreshSidebar() {
	var out map[string]interface{}
	if err := rc.api("GET", "/api/status", nil, &out); err != nil {
		rc.sidebar.SetText(strings.Join([]string{
			"remote",
			"  " + rc.base,
			"  login required or offline",
			"",
			"commands",
			"  login <user> <pass>",
			"  status",
			"  reload",
			"  blocklists",
			"  upstreams",
			"  quit",
		}, "\n"))
		return
	}
	host := mapString(out, "host")
	stats := mapString(out, "stats")
	lines := []string{
		"remote",
		"  " + rc.base,
		"",
		"status",
		fmt.Sprintf("  uptime: %v", out["uptime"]),
		fmt.Sprintf("  memory: %v", host["memory"]),
		fmt.Sprintf("  cpu:    %v", host["cpu"]),
		fmt.Sprintf("  listen: %v", out["listen"]),
		fmt.Sprintf("  web:    %v", out["http"]),
		"",
		"queries",
		fmt.Sprintf("  total:     %v", stats["total_queries"]),
		fmt.Sprintf("  blocked:   %v", stats["blocked"]),
		fmt.Sprintf("  local:     %v", stats["local"]),
		fmt.Sprintf("  cached:    %v", stats["cached"]),
		fmt.Sprintf("  forwarded: %v", stats["forwarded"]),
		"",
		"config",
		fmt.Sprintf("  records:   %v", out["records_count"]),
		fmt.Sprintf("  blocked:   %v", out["blocked_count"]),
		fmt.Sprintf("  upstreams: %v/%v", out["active_upstreams"], out["upstream_count"]),
		fmt.Sprintf("  clients:   %v", out["client_count"]),
		"",
		"main navigation",
		"  dashboard",
		"  query log",
		"  clients",
		"",
		"dns control",
		"  local dns",
		"  blocklists",
		"  profiles",
		"  upstreams",
		"",
		"system",
		"  settings",
		"  certificates",
		"  server log",
		"  users",
	}
	rc.sidebar.SetText(strings.Join(lines, "\n"))
}

func mapString(v map[string]interface{}, key string) map[string]interface{} {
	if m, ok := v[key].(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func (rc *remoteConsole) run(command string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	if strings.EqualFold(fields[0], "login") {
		if len(fields) >= 2 {
			rc.append("> login " + fields[1] + " ******")
		} else {
			rc.append("> login")
		}
	} else {
		rc.append("> " + command)
	}
	switch strings.ToLower(fields[0]) {
	case "quit", "exit":
		rc.app.Stop()
	case "clear":
		rc.mu.Lock()
		rc.lines = nil
		rc.mu.Unlock()
		rc.refresh()
	case "login":
		if len(fields) < 3 {
			rc.append("usage: login <username> <password>")
			return
		}
		var out map[string]interface{}
		if err := rc.api("POST", "/api/login", map[string]string{"username": fields[1], "password": fields[2]}, &out); err != nil {
			rc.append("login failed: " + err.Error())
			return
		}
		rc.append("logged in")
	case "status":
		var out map[string]interface{}
		if err := rc.api("GET", "/api/status", nil, &out); err != nil {
			rc.append("status failed: " + err.Error())
			return
		}
		rc.append(fmt.Sprintf("uptime=%v blocked=%v queries=%v clients=%v", out["uptime"], out["blocked_count"], out["stats"], out["client_count"]))
	case "reload":
		var out map[string]interface{}
		if err := rc.api("POST", "/api/reload", map[string]string{}, &out); err != nil {
			rc.append("reload failed: " + err.Error())
			return
		}
		rc.append(fmt.Sprintf("gravity updated, blocked=%v", out["blocked_count"]))
	case "blocklists":
		var lists []BlocklistSource
		if err := rc.api("GET", "/api/blocklists", nil, &lists); err != nil {
			rc.append("blocklists failed: " + err.Error())
			return
		}
		for _, l := range lists {
			state := "disabled"
			if l.Enabled {
				state = "enabled"
			}
			rc.append(fmt.Sprintf("%s  %s  loaded=%d  %s", l.Source, state, l.LastLoaded, l.LastError))
		}
	case "upstreams":
		var ups []map[string]interface{}
		if err := rc.api("GET", "/api/upstreams", nil, &ups); err != nil {
			rc.append("upstreams failed: " + err.Error())
			return
		}
		for _, up := range ups {
			rc.append(fmt.Sprintf("%v enabled=%v", up["address"], up["enabled"]))
		}
	default:
		rc.append("unknown remote command")
	}
}

func (rc *remoteConsole) api(method, path string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, rc.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-DNSLeaf-Request", "1")
	resp, err := rc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (ui *consoleUI) wake() {}

func (ui *consoleUI) refreshSidebar() {
	d := ui.dad
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	d.statsMu.Lock()
	s := d.stats
	d.statsMu.Unlock()
	d.blockMu.RLock()
	blockedCount := d.blockedCountLocked()
	d.blockMu.RUnlock()
	clients := d.clientList()
	active := len(d.activeUpstreams())
	policy := "open"
	if d.cfg.WhitelistOnly {
		policy = "whitelist"
	} else if d.cfg.LANOnly {
		policy = "LAN only"
	}
	lines := []string{
		"status",
		fmt.Sprintf("  uptime: %s", time.Since(d.started).Truncate(time.Second)),
		fmt.Sprintf("  memory: %s", processMemory()),
		fmt.Sprintf("  listen: %s", d.cfg.Listen),
		fmt.Sprintf("  web:    %s", d.cfg.HTTP),
		fmt.Sprintf("  policy: %s", policy),
		"",
		"queries",
		fmt.Sprintf("  total:     %d", s.Queries),
		fmt.Sprintf("  blocked:   %d", s.Blocked),
		fmt.Sprintf("  local:     %d", s.Local),
		fmt.Sprintf("  cached:    %d", s.Cached),
		fmt.Sprintf("  forwarded: %d", s.Forwarded),
		"",
		"config",
		fmt.Sprintf("  records:   %d", len(d.cfg.Records)),
		fmt.Sprintf("  blocked:   %d", blockedCount),
		fmt.Sprintf("  upstreams: %d/%d", active, len(d.cfg.Upstreams)),
		fmt.Sprintf("  clients:   %d", len(clients)),
	}
	ui.sidebar.SetText(strings.Join(lines, "\n"))
}

func (ui *consoleUI) refreshLog() {
	ui.mu.Lock()
	lines := append([]string(nil), ui.lines...)
	ui.mu.Unlock()
	ui.log.SetText(strings.Join(lines, "\n"))
	ui.log.ScrollToEnd()
}

func (ui *consoleUI) appendLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	ui.mu.Lock()
	ui.lines = append(ui.lines, line)
	if len(ui.lines) > 1000 {
		ui.lines = ui.lines[len(ui.lines)-1000:]
	}
	running := ui.running
	inCommand := ui.inCommand
	ui.mu.Unlock()
	if ui.app != nil && running && !inCommand {
		ui.app.QueueUpdateDraw(func() {
			ui.refreshLog()
		})
		return
	}
	ui.refreshLog()
}

func (ui *consoleUI) runCommand(command string) {
	ui.mu.Lock()
	ui.inCommand = true
	ui.mu.Unlock()
	defer func() {
		ui.mu.Lock()
		ui.inCommand = false
		ui.mu.Unlock()
	}()
	ui.appendLog("> " + command)
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	d := ui.dad
	d.cfgMu.Lock()
	defer func() {
		d.cfgMu.Unlock()
		ui.refreshSidebar()
	}()
	switch strings.ToLower(fields[0]) {
	case "help":
		ui.appendLog(strings.Join([]string{
			"help                         show commands",
			"clear                        clear console",
			"status                       print server status",
			"clients                      list known clients",
			"blocklists                   list subscribed blocklists",
			"blocklist add <name> <src>   add local path or URL",
			"blocklist enable <src>       enable subscribed list",
			"blocklist disable <src>      disable subscribed list",
			"blocklist remove <src>       remove subscribed list",
			"gravity [list]               refresh all or one blocklist",
			"reload                       reload all blocklists",
			"users                        list panel users",
			"user add <u> <p> [role]      add panel user",
			"user reset <u> <p>           reset password",
			"user role <u> <role>         set admin/viewer",
			"user remove <u>              remove panel user",
			"whitelist                    list allowed IPs/CIDRs",
			"whitelist add <ip|cidr>      allow client",
			"whitelist remove <ip|cidr>   remove allowed client",
			"upstreams                    list upstreams",
			"upstream add <addr>          add upstream",
			"upstream enable <addr>       enable upstream",
			"upstream disable <addr>      disable upstream",
			"upstream remove <addr>       remove upstream",
			"settings                     print key settings",
			"quit                         exit dnsleaf",
		}, "\n"))
	case "clear":
		ui.mu.Lock()
		ui.lines = nil
		ui.mu.Unlock()
		ui.refreshLog()
	case "status":
		d.statsMu.Lock()
		s := d.stats
		d.statsMu.Unlock()
		ui.appendLog(fmt.Sprintf("uptime=%s listen=%s web=%s queries=%d blocked=%d local=%d cached=%d forwarded=%d",
			time.Since(d.started).Truncate(time.Second), d.cfg.Listen, d.cfg.HTTP, s.Queries, s.Blocked, s.Local, s.Cached, s.Forwarded))
	case "clients":
		clients := d.clientList()
		if len(clients) == 0 {
			ui.appendLog("No clients yet.")
			return
		}
		for _, c := range clients {
			name := c.Name
			if name == "" {
				name = "-"
			}
			ui.appendLog(fmt.Sprintf("%s  name=%s allowed=%t lan=%t whitelist=%t queries=%d denied=%d last=%s", c.IP, name, c.Allowed, c.LAN, c.Whitelisted, c.Queries, c.Denied, c.LastSeen))
		}
	case "users":
		if len(d.cfg.Auth.Users) == 0 {
			ui.appendLog("No users configured.")
			return
		}
		for _, user := range d.cfg.Auth.Users {
			ui.appendLog(fmt.Sprintf("%s  role=%s created=%s", user.Username, user.Role, user.CreatedAt))
		}
	case "user":
		ui.runUserCommand(fields[1:])
	case "blocklists":
		ui.runBlocklistsCommand()
	case "blocklist":
		ui.runBlocklistCommand(fields[1:])
	case "reload":
		d.resetBlocked()
		d.initBlocked()
		if err := d.loadBlocklist(); err != nil {
			ui.appendLog(fmt.Sprintf("reload failed: %v", err))
		} else {
			ui.appendLog("blocklists reloaded")
		}
	case "gravity":
		target := ""
		if len(fields) > 1 {
			target = strings.Join(fields[1:], " ")
		}
		if err := d.refreshBlocklistTarget(target); err != nil {
			ui.appendLog(fmt.Sprintf("gravity failed: %v", err))
		} else if target == "" {
			if err := d.saveConfig(); err != nil {
				ui.appendLog(fmt.Sprintf("gravity save failed: %v", err))
				return
			}
			ui.appendLog("gravity updated")
		} else {
			if err := d.saveConfig(); err != nil {
				ui.appendLog(fmt.Sprintf("gravity save failed: %v", err))
				return
			}
			ui.appendLog("gravity updated " + target)
		}
	case "whitelist":
		ui.runWhitelistCommand(fields[1:])
	case "upstreams":
		ui.runUpstreamsCommand()
	case "upstream":
		ui.runUpstreamCommand(fields[1:])
	case "settings":
		ui.appendLog(fmt.Sprintf("listen=%s web=%s cache=%t cache_size=%d cache_ttl=%ds lan_only=%t whitelist_only=%t blocklist=%s",
			d.cfg.Listen, d.cfg.HTTP, d.cfg.Cache, d.cfg.CacheSize, d.cfg.CacheTTL, d.cfg.LANOnly, d.cfg.WhitelistOnly, d.cfg.Blocklist))
	case "quit", "exit":
		d.Stop()
		return
	default:
		ui.appendLog("Unknown command. Type 'help'.")
	}
}

func (ui *consoleUI) runUserCommand(args []string) {
	if len(args) == 0 {
		ui.appendLog("usage: user add|reset|role|remove ...")
		return
	}
	d := ui.dad
	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) < 3 {
			ui.appendLog("usage: user add <username> <password> [admin|viewer]")
			return
		}
		role := "viewer"
		if len(args) >= 4 {
			role = args[3]
		}
		if role != "admin" && role != "viewer" {
			ui.appendLog("role must be admin or viewer")
			return
		}
		if !validUsername(args[1]) || args[2] == "" || len(args[2]) > 4096 {
			ui.appendLog("username and password are invalid")
			return
		}
		if _, ok := d.findUser(args[1]); ok {
			ui.appendLog("user already exists")
			return
		}
		d.cfg.Auth.Enabled = true
		d.cfg.Auth.Users = append(d.cfg.Auth.Users, UserAuth{Username: args[1], PasswordHash: passwordHash(args[2]), Role: role, CreatedAt: time.Now().Format(time.RFC3339)})
		if err := d.saveConfig(); err != nil {
			ui.appendLog(fmt.Sprintf("save failed: %v", err))
			return
		}
		ui.appendLog(fmt.Sprintf("added user %s as %s", args[1], role))
	case "reset":
		if len(args) < 3 {
			ui.appendLog("usage: user reset <username> <password>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				d.cfg.Auth.Users[i].PasswordHash = passwordHash(args[2])
				if err := d.saveConfig(); err != nil {
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("reset password for %s", args[1]))
				return
			}
		}
		ui.appendLog("user not found")
	case "role":
		if len(args) < 3 || (args[2] != "admin" && args[2] != "viewer") {
			ui.appendLog("usage: user role <username> <admin|viewer>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				if user.Role == "admin" && args[2] != "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot demote the last administrator")
					return
				}
				d.cfg.Auth.Users[i].Role = args[2]
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users[i] = user
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("updated %s to %s", args[1], args[2]))
				return
			}
		}
		ui.appendLog("user not found")
	case "remove":
		if len(args) < 2 {
			ui.appendLog("usage: user remove <username>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				if len(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot remove the last user")
					return
				}
				if user.Role == "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot remove the last administrator")
					return
				}
				users := append([]UserAuth(nil), d.cfg.Auth.Users...)
				d.cfg.Auth.Users = append(d.cfg.Auth.Users[:i], d.cfg.Auth.Users[i+1:]...)
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users = users
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("removed %s", args[1]))
				return
			}
		}
		ui.appendLog("user not found")
	default:
		ui.appendLog("usage: user add|reset|role|remove ...")
	}
}

func (ui *consoleUI) runBlocklistsCommand() {
	d := ui.dad
	if len(d.cfg.Blocklists) == 0 {
		ui.appendLog("No blocklists configured.")
		return
	}
	for i, list := range d.cfg.Blocklists {
		state := "enabled"
		if !list.Enabled {
			state = "disabled"
		}
		errText := ""
		if list.LastError != "" {
			errText = " error=" + list.LastError
		}
		ui.appendLog(fmt.Sprintf("%d  %s  %s  source=%s loaded=%d refreshed=%s exceptions=%d%s", i+1, list.Name, state, list.Source, list.LastLoaded, list.LastRefreshed, len(list.Allowlist), errText))
	}
}

func (ui *consoleUI) runBlocklistCommand(args []string) {
	if len(args) < 2 {
		ui.appendLog("usage: blocklist add|enable|disable|remove ...")
		return
	}
	d := ui.dad
	action := strings.ToLower(args[0])
	switch action {
	case "add":
		if len(args) < 3 {
			ui.appendLog("usage: blocklist add <name> <source>")
			return
		}
		d.cfg.Blocklists = append(d.cfg.Blocklists, BlocklistSource{Name: args[1], Source: args[2], Enabled: true})
		_ = d.saveConfig()
		ui.appendLog("added blocklist " + args[1])
	case "enable", "disable":
		source := args[1]
		for i := range d.cfg.Blocklists {
			if d.cfg.Blocklists[i].Source == source {
				d.cfg.Blocklists[i].Enabled = action == "enable"
				_ = d.saveConfig()
				ui.appendLog(action + "d blocklist " + source)
				return
			}
		}
		ui.appendLog("blocklist not found")
	case "remove":
		source := args[1]
		next := d.cfg.Blocklists[:0]
		found := false
		for _, list := range d.cfg.Blocklists {
			if list.Source == source {
				found = true
				continue
			}
			next = append(next, list)
		}
		d.cfg.Blocklists = next
		_ = d.saveConfig()
		if found {
			ui.appendLog("removed blocklist " + source)
		} else {
			ui.appendLog("blocklist not found")
		}
	default:
		ui.appendLog("usage: blocklist add|enable|disable|remove ...")
	}
}

func (ui *consoleUI) runWhitelistCommand(args []string) {
	d := ui.dad
	if len(args) == 0 || args[0] == "list" {
		if len(d.cfg.Whitelist) == 0 {
			ui.appendLog("Whitelist is empty.")
			return
		}
		ui.appendLog(strings.Join(d.cfg.Whitelist, "\n"))
		return
	}
	if len(args) < 2 {
		ui.appendLog("usage: whitelist add|remove <ip|cidr>")
		return
	}
	item := strings.TrimSpace(args[1])
	switch strings.ToLower(args[0]) {
	case "add":
		if !ipInList(item, d.cfg.Whitelist) {
			d.cfg.Whitelist = append(d.cfg.Whitelist, item)
			_ = d.saveConfig()
		}
		ui.appendLog("whitelisted " + item)
	case "remove":
		next := d.cfg.Whitelist[:0]
		for _, existing := range d.cfg.Whitelist {
			if existing != item {
				next = append(next, existing)
			}
		}
		d.cfg.Whitelist = next
		_ = d.saveConfig()
		ui.appendLog("removed whitelist entry " + item)
	default:
		ui.appendLog("usage: whitelist add|remove <ip|cidr>")
	}
}

func (ui *consoleUI) runUpstreamsCommand() {
	d := ui.dad
	if len(d.cfg.Upstreams) == 0 {
		ui.appendLog("No upstreams configured.")
		return
	}
	for _, addr := range d.cfg.Upstreams {
		state := "enabled"
		if d.disabledUpstream(addr) {
			state = "disabled"
		}
		ui.appendLog(fmt.Sprintf("%s  %s", addr, state))
	}
}

func (ui *consoleUI) runUpstreamCommand(args []string) {
	if len(args) < 2 {
		ui.appendLog("usage: upstream add|enable|disable|remove <addr>")
		return
	}
	d := ui.dad
	action := strings.ToLower(args[0])
	addr := strings.TrimSpace(args[1])
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	switch action {
	case "add":
		d.cfg.Upstreams = append(d.cfg.Upstreams, addr)
		_ = d.saveConfig()
		ui.appendLog("added upstream " + addr)
	case "enable", "disable":
		next := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != addr {
				next = append(next, item)
			}
		}
		if action == "disable" {
			next = append(next, addr)
		}
		d.cfg.DisabledUpstreams = next
		_ = d.saveConfig()
		ui.appendLog(action + "d upstream " + addr)
	case "remove":
		nextUp := d.cfg.Upstreams[:0]
		for _, item := range d.cfg.Upstreams {
			if item != addr {
				nextUp = append(nextUp, item)
			}
		}
		d.cfg.Upstreams = nextUp
		nextDisabled := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != addr {
				nextDisabled = append(nextDisabled, item)
			}
		}
		d.cfg.DisabledUpstreams = nextDisabled
		_ = d.saveConfig()
		ui.appendLog("removed upstream " + addr)
	default:
		ui.appendLog("usage: upstream add|enable|disable|remove <addr>")
	}
}

func newHTTPServer(addr string, handler http.Handler, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ErrorLog:          errorLog,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func (d *DNSLeaf) isStopping() bool {
	d.stopMu.Lock()
	stopped := d.stopped
	d.stopMu.Unlock()
	return stopped
}

func (d *DNSLeaf) registerDNSServer(server *dns.Server) {
	d.stopMu.Lock()
	d.serversMu.Lock()
	if d.stopped {
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.ShutdownContext(ctx)
		cancel()
		if server.PacketConn != nil {
			_ = server.PacketConn.Close()
		}
		if server.Listener != nil {
			_ = server.Listener.Close()
		}
		return
	}
	d.dnsServers = append(d.dnsServers, server)
	d.serversMu.Unlock()
	d.stopMu.Unlock()
}

func (d *DNSLeaf) registerHTTPServer(server *http.Server, listener net.Listener) {
	d.stopMu.Lock()
	d.serversMu.Lock()
	if d.stopped {
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		if listener != nil {
			_ = listener.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
		return
	}
	d.httpServers = append(d.httpServers, server)
	if listener != nil {
		d.httpListeners = append(d.httpListeners, listener)
	}
	d.serversMu.Unlock()
	d.stopMu.Unlock()
}

func (d *DNSLeaf) registerProxyListener(listener net.Listener) {
	d.stopMu.Lock()
	d.serversMu.Lock()
	if d.stopped {
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		_ = listener.Close()
		return
	}
	d.proxyListeners = append(d.proxyListeners, listener)
	d.serversMu.Unlock()
	d.stopMu.Unlock()
}

func (d *DNSLeaf) Stop() {
	d.stopOnce.Do(func() {
		d.stopMu.Lock()
		d.stopped = true
		close(d.stopCh)
		d.serversMu.Lock()
		dnsServers := append([]*dns.Server(nil), d.dnsServers...)
		httpServers := append([]*http.Server(nil), d.httpServers...)
		httpListeners := append([]net.Listener(nil), d.httpListeners...)
		proxyListeners := append([]net.Listener(nil), d.proxyListeners...)
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for _, server := range dnsServers {
			if err := server.ShutdownContext(ctx); err != nil {
				if server.PacketConn != nil {
					_ = server.PacketConn.Close()
				}
				if server.Listener != nil {
					_ = server.Listener.Close()
				}
			}
		}
		for _, server := range httpServers {
			_ = server.Shutdown(ctx)
		}
		for _, listener := range httpListeners {
			_ = listener.Close()
		}
		for _, listener := range proxyListeners {
			_ = listener.Close()
		}
		cancel()
		if d.ui != nil && d.ui.app != nil {
			d.ui.app.Stop()
		}
		d.stopPersistentState()
	})
}

func (d *DNSLeaf) markDNSReady() {
	d.readyMu.Lock()
	d.dnsReady++
	d.readyMu.Unlock()
}

func (d *DNSLeaf) markHTTPReady() {
	d.readyMu.Lock()
	d.httpReady++
	d.readyMu.Unlock()
}

func (d *DNSLeaf) markStartupFailure(err error) {
	if err == nil {
		return
	}
	d.readyMu.Lock()
	d.startupErr = err.Error()
	d.readyMu.Unlock()
}

func (d *DNSLeaf) Start(useTUI bool) error {
	d.ensureAuth()
	d.cfgMu.RLock()
	if err := validateConfig(d.cfg); err != nil {
		d.cfgMu.RUnlock()
		return err
	}
	d.cfgMu.RUnlock()
	if useTUI {
		ui, err := newConsoleUI(d)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[DNSLeaf] tui init error: %v\n", err)
		} else {
			d.ui = ui
		}
	}
	d.initBlocked()
	if err := d.loadLocalBlocklists(); err != nil {
		d.consoleLogf("[DNSLeaf] blocklist error: %v", err)
	}
	d.cfgMu.RLock()
	cfg := d.cfg
	d.cfgMu.RUnlock()
	var dotTLSConfig *tls.Config
	var httpsTLSConfig *tls.Config
	if cfg.DoT != "" || cfg.HTTPS != "" {
		cert, err := tls.LoadX509KeyPair(d.runtimePath(cfg.TLSCert), d.runtimePath(cfg.TLSKey))
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		if cfg.DoT != "" {
			dotTLSConfig = tlsConfig.Clone()
		}
		if cfg.HTTPS != "" {
			httpsTLSConfig = tlsConfig.Clone()
		}
	}
	udpConn, err := net.ListenPacket("udp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("UDP: %w", err)
	}
	tcpListener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		_ = udpConn.Close()
		return fmt.Errorf("TCP: %w", err)
	}
	httpListener, err := net.Listen("tcp", cfg.HTTP)
	if err != nil {
		_ = udpConn.Close()
		_ = tcpListener.Close()
		return fmt.Errorf("HTTP: %w", err)
	}
	var httpsListener net.Listener
	if cfg.HTTPS != "" {
		rawListener, listenErr := net.Listen("tcp", cfg.HTTPS)
		if listenErr != nil {
			_ = udpConn.Close()
			_ = tcpListener.Close()
			_ = httpListener.Close()
			return fmt.Errorf("HTTPS: %w", listenErr)
		}
		httpsListener = tls.NewListener(rawListener, httpsTLSConfig)
	}
	var dotListener net.Listener
	if cfg.DoT != "" {
		rawListener, listenErr := net.Listen("tcp", cfg.DoT)
		if listenErr != nil {
			_ = udpConn.Close()
			_ = tcpListener.Close()
			_ = httpListener.Close()
			if httpsListener != nil {
				_ = httpsListener.Close()
			}
			return fmt.Errorf("DoT: %w", listenErr)
		}
		dotListener = tls.NewListener(rawListener, dotTLSConfig)
	}

	errCh := make(chan error, 8)
	dnsHandler := dns.HandlerFunc(d.HandleDNS)
	udpServer := &dns.Server{Addr: cfg.Listen, Net: "udp", PacketConn: udpConn, Handler: dnsHandler, NotifyStartedFunc: d.markDNSReady}
	tcpServer := &dns.Server{Addr: cfg.Listen, Net: "tcp", Listener: tcpListener, Handler: dnsHandler, NotifyStartedFunc: d.markDNSReady}
	d.registerDNSServer(udpServer)
	d.registerDNSServer(tcpServer)
	go func() {
		d.consoleLogf("[DNSLeaf] DNS listening on %s (UDP)", cfg.Listen)
		if err := udpServer.ActivateAndServe(); err != nil && !d.isStopping() {
			wrapped := fmt.Errorf("UDP: %w", err)
			d.markStartupFailure(wrapped)
			errCh <- wrapped
		}
	}()
	go func() {
		d.consoleLogf("[DNSLeaf] DNS listening on %s (TCP)", cfg.Listen)
		if err := tcpServer.ActivateAndServe(); err != nil && !d.isStopping() {
			wrapped := fmt.Errorf("TCP: %w", err)
			d.markStartupFailure(wrapped)
			errCh <- wrapped
		}
	}()
	if dotListener != nil {
		dotServer := &dns.Server{Addr: cfg.DoT, Net: "tcp-tls", Listener: dotListener, TLSConfig: dotTLSConfig, Handler: dnsHandler, NotifyStartedFunc: d.markDNSReady}
		d.registerDNSServer(dotServer)
		go func() {
			d.consoleLogf("[DNSLeaf] DNS-over-TLS listening on %s", cfg.DoT)
			if err := dotServer.ActivateAndServe(); err != nil && !d.isStopping() {
				wrapped := fmt.Errorf("DoT: %w", err)
				d.markStartupFailure(wrapped)
				errCh <- wrapped
			}
		}()
	}
	if cfg.HTTPProxyEnabled && strings.TrimSpace(cfg.HTTPProxy) != "" {
		go func() {
			if err := d.serveHTTPProxy(strings.TrimSpace(cfg.HTTPProxy)); err != nil && !d.isStopping() {
				errCh <- fmt.Errorf("HTTP proxy: %w", err)
			}
		}()
	}
	if cfg.SOCKSProxyEnabled && strings.TrimSpace(cfg.SOCKSProxy) != "" {
		go func() {
			if err := d.serveSOCKSProxy(strings.TrimSpace(cfg.SOCKSProxy)); err != nil && !d.isStopping() {
				errCh <- fmt.Errorf("SOCKS proxy: %w", err)
			}
		}()
	}
	go func() {
		d.cfgMu.RLock()
		hasRemote := d.hasRemoteBlocklists()
		d.cfgMu.RUnlock()
		if !hasRemote {
			return
		}
		d.consoleLogf("[DNSLeaf] updating remote blocklists in background")
		d.cfgMu.Lock()
		err := d.loadRemoteBlocklists()
		if err == nil {
			err = d.saveConfigLocked()
		}
		d.cfgMu.Unlock()
		if err != nil {
			d.consoleLogf("[DNSLeaf] remote blocklist error: %v", err)
			return
		}
		d.blockMu.RLock()
		bc := d.blockedCountLocked()
		d.blockMu.RUnlock()
		d.consoleLogf("[DNSLeaf] remote blocklists updated, %d blocked domains active", bc)
	}()
	go d.monitorUpstreams()

	mux := http.NewServeMux()
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/dnsleaf.png", d.handleLogo)
	mux.HandleFunc("/dns-query", d.handleDoH)
	mux.HandleFunc("/api/ping", d.handlePing)
	mux.HandleFunc("/api/healthz", d.handleHealthz)
	mux.HandleFunc("/api/readyz", d.handleReadyz)
	mux.HandleFunc("/metrics", d.handleMetrics)
	mux.HandleFunc("/api/session", d.handleSession)
	mux.HandleFunc("/api/login", d.handleLogin)
	mux.HandleFunc("/api/status", d.handleStatus)
	mux.HandleFunc("/api/records", d.handleRecords)
	mux.HandleFunc("/api/records/import", d.handleImportRecords)
	mux.HandleFunc("/api/blocked", d.handleBlocked)
	mux.HandleFunc("/api/blocked-ips", d.handleBlockedIPs)
	mux.HandleFunc("/api/regex-rules", d.handleRegexRules)
	mux.HandleFunc("/api/allowed", d.handleAllowed)
	mux.HandleFunc("/api/blocklists", d.handleBlocklists)
	mux.HandleFunc("/api/blocklists/entries", d.handleBlocklistEntries)
	mux.HandleFunc("/api/block-groups", d.handleBlockGroups)
	mux.HandleFunc("/api/upstreams", d.handleUpstreams)
	mux.HandleFunc("/api/profiles", d.handleProfiles)
	mux.HandleFunc("/api/profiles/", d.handleProfilePath)
	mux.HandleFunc("/api/clients/clear-denied", d.handleClearDeniedClients)
	mux.HandleFunc("/api/clients", d.handleClients)
	mux.HandleFunc("/api/clients/", d.handleClientProfilePath)
	mux.HandleFunc("/api/log", d.handleLog)
	mux.HandleFunc("/api/audit", d.handleAudit)
	mux.HandleFunc("/api/server-log", d.handleServerLog)
	mux.HandleFunc("/api/backup", d.handleBackup)
	mux.HandleFunc("/api/reload", d.handleReload)
	mux.HandleFunc("/api/gravity/start", d.handleGravityStart)
	mux.HandleFunc("/api/gravity/progress", d.handleGravityProgress)
	mux.HandleFunc("/api/settings", d.handleSettings)
	mux.HandleFunc("/api/tls/selfsigned", d.handleSelfSignedTLS)
	mux.HandleFunc("/api/users", d.handleUsers)

	handler := securityHeaders(versionedAPIHandler(d.configGuard(d.requireAuth(mux))))
	httpServer := newHTTPServer(cfg.HTTP, handler, log.New(serverLogWriter{dad: d}, "", 0))
	d.registerHTTPServer(httpServer, httpListener)
	d.markHTTPReady()
	go func() {
		d.consoleLogf("[DNSLeaf] Web UI at %s or %s", webURL(cfg.HTTP), portalURL(cfg.PortalHost, cfg.HTTPS, cfg.HTTP))
		if err := httpServer.Serve(httpListener); err != nil && !d.isStopping() && !errors.Is(err, http.ErrServerClosed) {
			wrapped := fmt.Errorf("HTTP: %w", err)
			d.markStartupFailure(wrapped)
			errCh <- wrapped
		}
	}()
	if httpsListener != nil {
		httpsServer := newHTTPServer(cfg.HTTPS, handler, log.New(serverLogWriter{dad: d}, "", 0))
		d.registerHTTPServer(httpsServer, httpsListener)
		d.markHTTPReady()
		go func() {
			d.consoleLogf("[DNSLeaf] HTTPS Web UI at %s or %s", webURL(cfg.HTTPS), portalURL(cfg.PortalHost, cfg.HTTPS, cfg.HTTP))
			if err := httpsServer.Serve(httpsListener); err != nil && !d.isStopping() && !errors.Is(err, http.ErrServerClosed) {
				wrapped := fmt.Errorf("HTTPS: %w", err)
				d.markStartupFailure(wrapped)
				errCh <- wrapped
			}
		}()
	}

	d.blockMu.RLock()
	bc := d.blockedCountLocked()
	d.blockMu.RUnlock()
	d.cfgMu.RLock()
	recordCount := len(d.cfg.Records)
	upstreamCount := len(d.cfg.Upstreams)
	d.cfgMu.RUnlock()
	d.consoleLogf("[DNSLeaf] %d blocked domains, %d local records, %d upstreams", bc, recordCount, upstreamCount)
	d.consoleLogf("[DNSLeaf] listeners bound; waiting for serving loops")

	if d.ui == nil {
		select {
		case err := <-errCh:
			return err
		case <-d.stopCh:
			return nil
		}
	}
	var runErr error
	var runErrMu sync.Mutex
	go func() {
		err := <-errCh
		runErrMu.Lock()
		runErr = err
		runErrMu.Unlock()
		d.consoleLogf("[DNSLeaf] fatal: %v", err)
		d.Stop()
	}()
	d.ui.mu.Lock()
	d.ui.running = true
	d.ui.mu.Unlock()
	if err := d.ui.app.Run(); err != nil {
		d.Stop()
		return err
	}
	d.ui.mu.Lock()
	d.ui.running = false
	d.ui.mu.Unlock()
	runErrMu.Lock()
	defer runErrMu.Unlock()
	d.Stop()
	return runErr
}

func printUsage() {
	fmt.Println("DNSLeaf - self-hosted DNS resolver and network policy manager")
	fmt.Println("usage: dnsleaf [--config path] [--no-tui] [command]")
	fmt.Println("commands: validate, user, service")
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--help", "-h", "help":
			printUsage()
			return
		}
	}
	cfgPath := "config.json"
	useTUI := true
	remoteMode := false
	remoteServer := ""
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--no-tui" {
			useTUI = false
			continue
		}
		if arg == "--remote" || arg == "-remote" {
			remoteMode = true
			continue
		}
		if arg == "--server" || arg == "-server" || arg == "server" {
			if i+1 < len(os.Args) {
				remoteServer = os.Args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--server=") {
			remoteServer = strings.TrimPrefix(arg, "--server=")
			continue
		}
		if strings.HasPrefix(arg, "-server=") {
			remoteServer = strings.TrimPrefix(arg, "-server=")
			continue
		}
		if strings.HasPrefix(arg, "server=") {
			remoteServer = strings.TrimPrefix(arg, "server=")
			continue
		}
		if arg == "--config" || arg == "-config" {
			if i+1 < len(os.Args) {
				cfgPath = os.Args[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if arg == "user" || arg == "service" {
			break
		}
		cfgPath = arg
		break
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DNSLeaf] config error: %v\n", err)
		os.Exit(1)
	}

	dad := NewDNSLeaf(cfg, cfgPath)
	defer dad.Stop()
	cliArgs := make([]string, 0, len(os.Args)-1)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--no-tui" {
			continue
		}
		if arg == "--remote" || arg == "-remote" {
			continue
		}
		if arg == "--server" || arg == "-server" || arg == "server" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--server=") || strings.HasPrefix(arg, "-server=") || strings.HasPrefix(arg, "server=") {
			continue
		}
		if arg == "--config" || arg == "-config" {
			i++
			continue
		}
		cliArgs = append(cliArgs, arg)
	}
	if len(cliArgs) > 0 && cliArgs[0] == cfgPath {
		cliArgs = cliArgs[1:]
	}
	if dad.handleCLI(cliArgs) {
		return
	}
	if remoteMode {
		server := remoteServer
		if server == "" {
			var err error
			server, err = promptRemoteServer(webURL(cfg.HTTP))
			if err != nil {
				fmt.Fprintf(os.Stderr, "[DNSLeaf] remote tui error: %v\n", err)
				os.Exit(1)
			}
		}
		if err := runRemoteConsoleBase(server); err != nil {
			fmt.Fprintf(os.Stderr, "[DNSLeaf] remote tui error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if useTUI && len(cliArgs) == 0 && runningDNSLeaf(cfg) {
		if err := runRemoteConsole(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[DNSLeaf] remote tui error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	dad.saveConfig()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n[DNSLeaf] shutting down")
		dad.Stop()
	}()

	if err := dad.Start(useTUI); err != nil && !dad.isStopping() {
		fmt.Fprintf(os.Stderr, "[DNSLeaf] fatal: %v\n", err)
		os.Exit(1)
	}
}
