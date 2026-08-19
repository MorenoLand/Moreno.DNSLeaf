package main

import (
	_ "embed"
	"fmt"
	"net"
	"net/http"
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
