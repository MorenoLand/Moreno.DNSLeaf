package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"mime"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

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
	LastRefreshed string   `json:"last_refreshed,omitempty"`
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
	BlockGroups        []BlockGroup             `json:"block_groups"`
	Cache              bool                     `json:"cache_enabled"`
	CacheSize          int                      `json:"cache_size"`
	CacheTTL           int                      `json:"cache_ttl_seconds"`
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
	gravity            []string
	gravityByList      map[string][]uint32
	blockMu            sync.RWMutex
	cache              map[string]cacheEntry
	cacheMu            sync.RWMutex
	stats              Stats
	statsMu            sync.Mutex
	log                []QueryEntry
	logMu              sync.Mutex
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
	stopCh             chan struct{}
	stopMu             sync.Mutex
	stopOnce           sync.Once
	stopped            bool
	dnsServers         []*dns.Server
	httpServers        []*http.Server
	proxyListeners     []net.Listener
	serversMu          sync.Mutex
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

const indexHTML = `<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="darkreader-lock">
<title>DNSLeaf</title>
<link rel="icon" type="image/png" href="/dnsleaf.png">
<style>
:root{color-scheme:dark;--bg:#1f272d;--bg2:#161d22;--side:#20282e;--top:#2b343b;--panel:#2b343b;--panel2:#242c32;--field:#20282e;--line:#3b474f;--line2:#4c5b64;--text:#edf3f6;--muted:#b1c0c8;--dim:#83939c;--blue:#3c8dbc;--blue2:#367fa9;--cyan:#00c0ef;--green:#00a65a;--red:#dd4b39;--yellow:#f39c12;--purple:#605ca8;--radius:4px}
*{margin:0;padding:0;box-sizing:border-box}
html,body{min-height:100%;background:var(--bg);forced-color-adjust:none}
body{font-family:"Segoe UI",Arial,sans-serif;color:var(--text);font-size:14px;line-height:1.42}
button,input,select{font:inherit}
.auth{position:fixed;inset:0;z-index:50;display:grid;place-items:center;padding:24px;background:#151a1d;background-image:radial-gradient(circle at 20% 10%,rgba(0,192,239,.12),transparent 28%),radial-gradient(circle at 80% 90%,rgba(0,166,90,.12),transparent 24%)}
.auth.hide{display:none}
.login{width:min(390px,100%);background:#2b343b;border-radius:6px;box-shadow:0 18px 55px rgba(0,0,0,.45);padding:26px 28px;border:1px solid rgba(255,255,255,.04);text-align:center}
.login .logo{margin:0 auto 12px}
.login h2{font-size:20px;font-weight:400;margin-bottom:14px}
.login .muted{text-align:left;margin:8px 0 6px}
.login input{width:100%;margin-top:10px}
.login button{width:100%;margin-top:12px}
.login-options{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;text-align:left}
.login-options label{display:flex;align-items:center;gap:7px;color:#c9d3d9;font-size:12px}
.login-options input{width:auto;margin:0;min-height:auto}
.login-links{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:18px}
.login-links span{background:#38434b;color:#c9d3d9;border-radius:var(--radius);padding:8px 4px;font-size:12px}
.err{color:#ff9b8e;font-size:13px;min-height:20px;margin-top:10px;text-align:left}
header{position:fixed;left:0;top:0;bottom:0;width:230px;background:var(--side);border-right:1px solid #151b1f;z-index:10;display:flex;flex-direction:column}
.brand{min-height:112px;background:#1b2227;border-bottom:1px solid #151b1f;display:flex;align-items:flex-start;gap:12px;padding:16px 18px}
.logo{width:42px;height:42px;display:block;flex:0 0 auto;object-fit:contain}
.brand h1{font-size:20px;font-weight:600;letter-spacing:.2px;line-height:1}
.service-status{font-size:12px;color:#c7d3da;margin-top:5px;display:block;line-height:1.5}
.service-line{display:flex;gap:6px;align-items:center}
.service-metrics{margin-top:5px;color:#b9c6cc;font-size:12px}
.service-metrics div{display:flex;justify-content:space-between;gap:12px;min-width:118px}
.service-metrics b{font-weight:600;color:#eef5f7}
.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 0 2px rgba(0,166,90,.2)}
nav{padding:10px 0;display:flex;flex-direction:column}
nav a,#logout{display:flex;align-items:center;gap:10px;color:#c8d3da;text-decoration:none;cursor:pointer;padding:11px 18px;border-left:4px solid transparent;font-size:14px}
nav a:hover,#logout:hover{background:#1b2227;color:#fff}
nav a.on{background:#1b2227;color:#fff;border-left-color:var(--blue)}
.nav-label{padding:15px 18px 7px 22px;color:#7d8a92;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}
.nav-label:first-child{padding-top:8px}
.ico{width:17px;height:17px;display:inline-block;position:relative;flex:0 0 17px;color:#b8c5cb;font-size:0}
.ico:before,.ico:after{content:"";position:absolute;box-sizing:border-box}
.ico.dash:before{left:2px;top:2px;width:5px;height:5px;background:currentColor;box-shadow:8px 0 0 currentColor,0 8px 0 currentColor,8px 8px 0 currentColor}
.ico.log:before{left:4px;right:2px;top:4px;height:2px;background:currentColor;box-shadow:0 5px 0 currentColor,0 10px 0 currentColor}
.ico.local:before{left:3px;top:7px;width:11px;height:8px;border:2px solid currentColor;border-top:0}.ico.local:after{left:3px;top:2px;width:11px;height:11px;border-left:2px solid currentColor;border-top:2px solid currentColor;transform:rotate(45deg)}
.ico.block:before{inset:2px;border:2px solid currentColor;border-radius:50%}.ico.block:after{left:4px;right:4px;top:7px;height:2px;background:currentColor;transform:rotate(-35deg)}
.ico.up:before{left:2px;right:2px;top:4px;height:2px;background:currentColor;box-shadow:0 8px 0 currentColor}.ico.up:after{right:2px;top:1px;border-left:6px solid currentColor;border-top:4px solid transparent;border-bottom:4px solid transparent;box-shadow:-10px 8px 0 -1px currentColor}
.ico.client:before{left:5px;top:2px;width:7px;height:7px;border-radius:50%;background:currentColor}.ico.client:after{left:2px;right:2px;bottom:2px;height:7px;border-radius:8px 8px 2px 2px;background:currentColor}
.ico.settings:before{inset:3px;border:3px solid currentColor;border-radius:50%}.ico.settings:after{left:7px;top:0;width:3px;height:17px;background:currentColor;box-shadow:0 0 0 0 currentColor;transform:rotate(45deg)}
.ico.cert:before{left:4px;top:2px;width:9px;height:13px;border:2px solid currentColor;border-radius:2px}.ico.cert:after{left:6px;top:10px;width:5px;height:2px;background:currentColor}
.ico.users:before{left:2px;top:3px;width:5px;height:5px;border-radius:50%;background:currentColor;box-shadow:8px 0 0 currentColor}.ico.users:after{left:1px;right:1px;bottom:3px;height:5px;border-radius:6px;background:currentColor}
nav .nav-label.main{order:1}nav .nav-label.dns{order:5}nav .nav-label.system{order:10}
nav a[data-t="dashboard"]{order:2}nav a[data-t="log"]{order:3}nav a[data-t="clients"]{order:4}nav a[data-t="records"]{order:6}nav a[data-t="blocklist"]{order:7}nav a[data-t="profiles"]{order:8}nav a[data-t="upstreams"]{order:9}nav a[data-t="settings"]{order:11}nav a[data-t="certs"]{order:12}nav a[data-t="proxy"]{order:13}nav a[data-t="serverlog"]{order:14}nav a[data-t="users"]{order:15}
nav a[data-t="dashboard"] .ico:before{left:2px;top:2px;width:5px;height:5px;background:currentColor;box-shadow:8px 0 0 currentColor,0 8px 0 currentColor,8px 8px 0 currentColor}
nav a[data-t="log"] .ico:before,nav a[data-t="serverlog"] .ico:before{left:4px;right:2px;top:4px;height:2px;background:currentColor;box-shadow:0 5px 0 currentColor,0 10px 0 currentColor}
nav a[data-t="records"] .ico:before{left:3px;top:7px;width:11px;height:8px;border:2px solid currentColor;border-top:0}nav a[data-t="records"] .ico:after{left:3px;top:2px;width:11px;height:11px;border-left:2px solid currentColor;border-top:2px solid currentColor;transform:rotate(45deg)}
nav a[data-t="blocklist"] .ico:before{inset:2px;border:2px solid currentColor;border-radius:50%}nav a[data-t="blocklist"] .ico:after{left:4px;right:4px;top:7px;height:2px;background:currentColor;transform:rotate(-35deg)}
nav a[data-t="profiles"] .ico:before{left:2px;top:2px;width:5px;height:5px;border-radius:50%;background:currentColor;box-shadow:8px 0 0 currentColor,4px 8px 0 currentColor}nav a[data-t="profiles"] .ico:after{left:1px;right:1px;bottom:1px;height:5px;border-radius:6px 6px 2px 2px;border:2px solid currentColor;border-top:0}
nav a[data-t="upstreams"] .ico:before{left:2px;right:2px;top:4px;height:2px;background:currentColor;box-shadow:0 8px 0 currentColor}nav a[data-t="upstreams"] .ico:after{right:2px;top:1px;border-left:6px solid currentColor;border-top:4px solid transparent;border-bottom:4px solid transparent;box-shadow:-10px 8px 0 -1px currentColor}
nav a[data-t="clients"] .ico:before{left:5px;top:2px;width:7px;height:7px;border-radius:50%;background:currentColor}nav a[data-t="clients"] .ico:after{left:2px;right:2px;bottom:2px;height:7px;border-radius:8px 8px 2px 2px;background:currentColor}
nav a[data-t="settings"] .ico:before{inset:3px;border:3px solid currentColor;border-radius:50%}nav a[data-t="settings"] .ico:after{left:7px;top:0;width:3px;height:17px;background:currentColor;transform:rotate(45deg)}
nav a[data-t="certs"] .ico:before{left:4px;top:2px;width:9px;height:13px;border:2px solid currentColor;border-radius:2px}nav a[data-t="certs"] .ico:after{left:6px;top:10px;width:5px;height:2px;background:currentColor}
nav a[data-t="proxy"] .ico:before{left:2px;top:6px;width:12px;height:5px;border:2px solid currentColor;border-radius:6px}nav a[data-t="proxy"] .ico:after{left:7px;top:2px;width:2px;height:13px;background:currentColor;box-shadow:-5px 6px 0 currentColor,5px 6px 0 currentColor}
nav a[data-t="users"] .ico:before{left:2px;top:3px;width:5px;height:5px;border-radius:50%;background:currentColor;box-shadow:8px 0 0 currentColor}nav a[data-t="users"] .ico:after{left:1px;right:1px;bottom:3px;height:5px;border-radius:6px;background:currentColor}
.account{margin-top:auto;border-top:1px solid #151b1f;padding:14px 18px 18px;background:#1b2227}
.account-label{font-size:11px;color:#8a989f;text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}
.account-user{font-size:14px;font-weight:600}
.account-role{display:none}
#logout{margin-top:12px;border:1px solid #3b474f;border-radius:var(--radius);padding:8px 10px;justify-content:center}
main{margin-left:230px;min-height:100vh;background:var(--bg);padding:0 22px 28px}
.tp{display:none}.tp.on{display:block}
.page-head{margin:0 -22px 18px;padding:16px 22px;background:#252e34;border-bottom:1px solid #141a1e;display:flex;gap:16px;align-items:center;justify-content:space-between}
.page-title h2{font-size:24px;font-weight:400}
.page-title p{color:#bac6cc;margin-top:2px}
.toolbar,.fr{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.toolbar{justify-content:flex-end;flex:1}
.toolbar input{max-width:600px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin-bottom:16px}
.sc{position:relative;overflow:hidden;border-radius:var(--radius);min-height:118px;padding:18px 18px;color:#fff;background:var(--blue);box-shadow:0 2px 0 rgba(0,0,0,.14)}
.sc:nth-child(2){background:var(--red)}.sc:nth-child(3){background:var(--green)}.sc:nth-child(4){background:var(--yellow)}.sc:nth-child(5){background:var(--purple)}.sc:nth-child(6){background:#a53a2d}
.sc .v{font-size:42px;font-weight:700;line-height:1;margin-top:12px;letter-spacing:.01em}
.sc .l{font-size:17px;margin-top:0;opacity:.98}
.wm{position:absolute;right:16px;bottom:12px;width:96px;height:96px;opacity:.2;pointer-events:none;background:center/contain no-repeat}
.wm.globe{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' stroke='%23000' stroke-width='7' stroke-linecap='round'%3E%3Ccircle cx='50' cy='50' r='36'/%3E%3Cpath d='M14 50h72M50 14c13 13 13 59 0 72M50 14c-13 13-13 59 0 72'/%3E%3C/g%3E%3C/svg%3E")}
.wm.hand{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' stroke='%23000' stroke-width='8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M34 12h32l22 22v32L66 88H34L12 66V34z'/%3E%3Cpath d='M30 50h40'/%3E%3C/g%3E%3C/svg%3E")}
.wm.house{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' stroke='%23000' stroke-width='8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M17 48L50 20l33 28'/%3E%3Cpath d='M27 45v35h46V45'/%3E%3Cpath d='M42 80V58h16v22'/%3E%3C/g%3E%3C/svg%3E")}
.wm.pie{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill='%23000' d='M54 10a40 40 0 1 1-30 12l30 30z'/%3E%3Cpath fill='%23000' opacity='.65' d='M60 8v36h35A40 40 0 0 0 60 8z'/%3E%3C/svg%3E")}
.wm.route{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' stroke='%23000' stroke-width='8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M18 32h54'/%3E%3Cpath d='M58 18l16 14-16 14'/%3E%3Cpath d='M82 68H28'/%3E%3Cpath d='M42 54L26 68l16 14'/%3E%3C/g%3E%3C/svg%3E")}
.wm.list{background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%23000'%3E%3Ccircle cx='25' cy='28' r='7'/%3E%3Ccircle cx='25' cy='50' r='7'/%3E%3Ccircle cx='25' cy='72' r='7'/%3E%3Crect x='40' y='22' width='42' height='12' rx='3'/%3E%3Crect x='40' y='44' width='42' height='12' rx='3'/%3E%3Crect x='40' y='66' width='42' height='12' rx='3'/%3E%3C/g%3E%3C/svg%3E")}
.grid{display:grid;grid-template-columns:1fr;gap:16px;align-items:start}
.dash-top{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(340px,.75fr);gap:16px;align-items:start}
.dash-main{display:flex;flex-direction:column;gap:16px}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.ii,.panel{background:var(--panel);border:1px solid #1a2024;border-top:3px solid var(--blue);border-radius:var(--radius);box-shadow:0 1px 2px rgba(0,0,0,.18)}
.ii{padding:13px 14px}
.ii .k{font-size:12px;color:#b6c4cb;text-transform:uppercase;letter-spacing:.04em}
.ii .kv{font-family:Consolas,"Courier New",monospace;margin-top:4px;color:#fff}
.panel{margin-bottom:16px}
.grid>.panel,.dash-main .panel,.dash-top .panel{margin-bottom:0}
.panel h2{font-size:16px;font-weight:400;padding:11px 14px;border-bottom:1px solid var(--line)}
.panel-body{padding:14px}
table{width:100%;border-collapse:collapse;background:transparent}
th,td{padding:10px 11px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}
th{font-size:12px;color:#d7e0e5;text-transform:uppercase;font-weight:600;background:#242c32}
tr:hover td{background:#242c32}
input,select,textarea{background:var(--field);border:1px solid var(--line2);color:#fff;padding:8px 10px;border-radius:var(--radius);min-height:36px}
textarea{min-height:92px;resize:vertical;font-family:inherit}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 2px rgba(0,192,239,.12)}
input::placeholder,textarea::placeholder{color:#8c9aa2}
button{background:var(--blue);border:1px solid var(--blue2);color:#fff;border-radius:var(--radius);padding:8px 13px;cursor:pointer;font-weight:600;min-height:36px}
button:hover{background:var(--blue2)}
.dg{background:var(--red);border-color:#c43e2d}.dg:hover{background:#c43e2d}
.ok{background:var(--green);border-color:#008d4c}.ok:hover{background:#008d4c}
.ghost{background:#3a464e;border-color:#59666f;color:#edf3f6}.ghost:hover{background:#46545d}
.sm{padding:4px 9px;font-size:12px;min-height:26px}
.tag{display:inline-block;padding:3px 8px;border-radius:2px;font-size:12px;font-weight:700;color:#fff;text-transform:uppercase}
.tag-blocked,.tag-error,.tag-denied{background:var(--red)}.tag-local,.tag-on{background:var(--green)}.tag-cached{background:var(--yellow)}.tag-forwarded{background:var(--blue)}.tag-trolled{background:#9b59b6}.tag-override{background:#16a085}.tag-off{background:#6c7a83}
.empty{color:#aebbc2;padding:24px;text-align:center}
.actions{display:grid;grid-template-columns:repeat(4,32px);gap:5px;min-width:143px}
.actions .sm{width:32px;height:30px;min-height:30px;padding:0;text-align:center}
.qlog{table-layout:fixed}
.qlog th:nth-child(1){width:74px}.qlog th:nth-child(2){width:130px}.qlog th:nth-child(3){width:82px}.qlog th:nth-child(6){width:70px}.qlog th:nth-child(7){width:95px}.qlog th:nth-child(8){width:54px}.qlog th:nth-child(9){width:156px}
.qlog td code{white-space:normal;word-break:break-word}
.qlog td{overflow:hidden}
.nowrap{white-space:nowrap}
.toast-wrap{position:fixed;right:18px;bottom:18px;z-index:80;display:flex;flex-direction:column;gap:8px;max-width:min(360px,calc(100vw - 36px))}
.toast{background:#1b2227;border:1px solid #3b474f;border-left:4px solid var(--blue);box-shadow:0 12px 30px rgba(0,0,0,.35);border-radius:var(--radius);padding:10px 12px;color:#edf3f6;font-size:13px}
.toast.ok{border-left-color:var(--green);background:#1d2c25}
.toast.err{border-left-color:var(--red);background:#2e2222}
.modal{position:fixed;inset:0;z-index:70;display:none;align-items:center;justify-content:center;background:rgba(10,14,17,.68);padding:24px}
.modal.show{display:flex}
.dialog{width:min(880px,calc(100vw - 48px));max-height:calc(100vh - 48px);background:#252e34;border:1px solid var(--line2);box-shadow:0 24px 70px rgba(0,0,0,.45);border-radius:var(--radius);display:flex;flex-direction:column}
.dialog-head{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:14px 16px;border-bottom:1px solid var(--line)}
.dialog-body{padding:16px;overflow:auto}
.console{background:#121719;border:1px solid var(--line);border-radius:var(--radius);min-height:320px;max-height:56vh;overflow:auto;white-space:pre-wrap;font-family:Consolas,"Courier New",monospace;line-height:1.45;color:#dff4e4;padding:12px}
.chart,.spark{background:#232b31;border:1px solid var(--line);border-radius:var(--radius)}
.chart{min-height:248px;padding:18px;display:grid;grid-template-columns:240px minmax(0,1fr);gap:22px;align-items:center}
.mix-donut{width:190px;aspect-ratio:1;border-radius:50%;background:conic-gradient(var(--blue) 0 var(--fwd),var(--yellow) var(--fwd) var(--cache),var(--green) var(--cache) var(--local),var(--red) var(--local) 100%);position:relative;margin:auto;box-shadow:inset 0 0 0 1px rgba(255,255,255,.08)}
.mix-donut:after{content:"";position:absolute;inset:45px;background:#232b31;border-radius:50%;box-shadow:inset 0 0 0 1px rgba(255,255,255,.08)}
.mix-total{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);width:88px;text-align:center;z-index:1;font-family:Consolas,"Courier New",monospace;font-size:20px;color:#fff}
.mix-total span{display:block;font-family:"Segoe UI",Arial,sans-serif;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#b8c7ce}
.mix-legend{display:grid;gap:10px}
.mix-row{display:grid;grid-template-columns:14px 110px minmax(0,1fr) 74px;gap:10px;align-items:center}
.mix-dot{width:12px;height:12px;border-radius:2px}
.mix-name{color:#dce7ec;font-weight:600}
.mix-track{height:12px;background:#1b2227;border:1px solid #37424a;border-radius:2px;overflow:hidden}
.mix-fill{height:100%;min-width:3px;box-shadow:inset 0 -5px 0 rgba(0,0,0,.12)}
.mix-val{text-align:right;font-family:Consolas,"Courier New",monospace;color:#fff}
.spark{height:406px;display:grid;grid-template-columns:78px minmax(0,1fr);grid-template-rows:24px minmax(0,1fr) 70px;overflow:hidden}
.spark-ytitle{grid-column:1;grid-row:1;color:#c4d0d6;font-size:12px;text-align:right;padding:6px 10px 0 0;text-transform:uppercase;letter-spacing:.05em}
.spark-xtitle{grid-column:2;grid-row:3;align-self:end;text-align:center;color:#c4d0d6;font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding-bottom:6px}
.spark-axis{grid-column:1;grid-row:2;display:flex;flex-direction:column;justify-content:space-between;align-items:flex-end;padding:0 10px 0 0;color:#c4d0d6;font-family:Consolas,"Courier New",monospace;font-size:13px;border-right:1px solid rgba(255,255,255,.18)}
.spark-plot{grid-column:2;grid-row:2;display:grid;gap:3px;align-items:end;padding:0 14px;background-image:linear-gradient(rgba(255,255,255,.16) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.10) 1px,transparent 1px);background-size:100% 20%,64px 100%;background-position:left bottom}
.spark-xaxis{grid-column:2;grid-row:3;display:grid;align-items:start;padding:26px 14px 0 14px;border-top:1px solid rgba(255,255,255,.18);color:#c4d0d6;font-family:Consolas,"Courier New",monospace;font-size:12px}
.spark-xaxis span{white-space:nowrap;transform:rotate(-32deg);transform-origin:left top}
.spark-col{height:var(--h);min-height:0;display:flex;flex-direction:column-reverse;border-radius:2px 2px 0 0;overflow:hidden;position:relative;background:transparent}
.spark-col.has{box-shadow:0 0 0 1px rgba(0,0,0,.12)}
.spark-seg{width:100%;min-height:1px}
.spark-seg.forwarded{background:var(--blue)}.spark-seg.blocked{background:var(--red)}.spark-seg.local{background:var(--green)}.spark-seg.cached{background:var(--yellow)}
.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
.setting-section{border-top:1px solid var(--line);padding-top:14px;margin-top:14px}
.setting-section:first-of-type{border-top:0;padding-top:0;margin-top:0}
.setting-title{font-size:12px;color:#d9e4e9;font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px}
.field{display:flex;flex-direction:column;gap:5px}
.field label{color:#edf3f6;font-size:13px;font-weight:600}
.field .hint{color:#aebbc2;font-size:12px;line-height:1.35}
.field input{width:100%}
.field textarea,.field select{width:100%}
.tog{display:flex;align-items:center;gap:9px;color:#dce7ec;background:var(--field);border:1px solid var(--line2);border-radius:var(--radius);padding:9px 11px;min-height:42px}
.tog input{width:auto;min-height:auto}
.muted{color:#aebbc2;font-size:13px}
code{font-family:Consolas,"Courier New",monospace;font-size:.94em;color:#fff}
.userbar,.nav-section{display:none}
@media(max-width:860px){header{position:static;width:auto}.brand{height:auto;padding:14px 18px}main{margin-left:0;padding:0 14px 20px}.page-head{margin:0 -14px 16px;display:block}.toolbar{margin-top:12px;justify-content:stretch}.toolbar input{max-width:none}.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
</style>
</head><body>
<div id="auth" class="auth">
<div class="login">
<img class="logo" src="/dnsleaf.png" alt="" aria-hidden="true">
<h2>DNSLeaf</h2>
<div class="muted">Sign in to manage DNS filtering, clients, blocklists, and resolver settings.</div>
<input id="login-user" placeholder="Username" autocomplete="username">
<input id="login-pass" type="password" placeholder="Password" autocomplete="current-password">
<div class="login-options"><label><input id="remember-user" type="checkbox"> Remember user</label></div>
<button id="btn-login">Sign in</button>
<div id="login-error" class="err"></div>
<div class="login-links"><span>Documentation</span><span>Console UI</span><span>Offline Ready</span></div>
</div>
</div>
<header>
<div class="brand"><img class="logo" src="/dnsleaf.png" alt="" aria-hidden="true"><div><h1>DNSLeaf</h1><div class="service-status"><div class="service-line"><span class="status-dot"></span><span id="svc-status">Resolver active</span></div><div class="service-metrics"><div><span>Uptime</span><b id="host-uptime">-</b></div><div><span>CPU</span><b id="host-cpu">-</b></div><div><span>Memory</span><b id="host-mem">-</b></div></div></div></div></div>
<nav id="tabs">
<div class="nav-label main">Main Navigation</div>
<div class="nav-label dns">DNS Control</div>
<div class="nav-label system">System</div>
<a class="on" data-t="dashboard"><span class="ico">▦</span>Dashboard</a>
<a data-t="log"><span class="ico">≡</span>Query Log</a>
<a data-t="records"><span class="ico">⌂</span>Local DNS</a>
<a data-t="blocklist"><span class="ico">⊘</span>Blocklists</a>
<a data-t="profiles"><span class="ico">◧</span>Profiles</a>
<a data-t="upstreams"><span class="ico">⇄</span>Upstreams</a>
<a data-t="clients"><span class="ico">◉</span>Clients</a>
<a data-t="settings"><span class="ico">⚙</span>Settings</a>
<a data-t="certs"><span class="ico">▣</span>Certificates</a>
<a data-t="proxy"><span class="ico">⇌</span>Proxy</a>
<a data-t="serverlog"><span class="ico">≡</span>Server Log</a>
<a data-t="users"><span class="ico">☷</span>Users</a>
</nav>
<div class="account"><div class="account-label">Signed in</div><div id="account-user" class="account-user">-</div><a id="logout">Logout</a></div>
</header>
<main>
<div id="t-dashboard" class="tp on">
<div class="page-head"><div class="page-title"><h2>Dashboard</h2><p>Live DNS filtering, resolver health, and client activity.</p></div></div>
<div class="stats">
<div class="sc"><div class="l">Total Queries</div><div class="v" id="s-q">-</div><span class="wm globe"></span></div>
<div class="sc"><div class="l">Blocked</div><div class="v" id="s-b">-</div><span class="wm hand"></span></div>
<div class="sc"><div class="l">Local</div><div class="v" id="s-l">-</div><span class="wm house"></span></div>
<div class="sc"><div class="l">Cached</div><div class="v" id="s-c">-</div><span class="wm pie"></span></div>
<div class="sc"><div class="l">Forwarded</div><div class="v" id="s-f">-</div><span class="wm route"><i></i></span></div>
<div class="sc"><div class="l">Domains on Blocklist</div><div class="v" id="s-d">-</div><span class="wm list"></span></div>
</div>
<div class="grid">
<div class="dash-top">
<div class="info" id="info"></div>
<div class="panel"><h2>Recent Clients</h2><table><thead><tr><th>Name</th><th>IP</th><th>Queries</th></tr></thead><tbody id="dash-clients"></tbody></table></div>
</div>
<div class="panel"><h2>Traffic Mix</h2><div class="panel-body"><div class="chart" id="chart"></div></div></div>
<div class="panel"><h2>Query Activity</h2><div class="panel-body"><div class="spark" id="activity"></div></div></div>
</div>
</div>
<div id="t-records" class="tp">
<div class="page-head"><div class="page-title"><h2>Local DNS Records</h2><p>Resolve LAN names and custom domains before forwarding upstream.</p></div></div>
<div class="panel"><h2>Add Record</h2><div class="panel-body"><div class="fr">
<input id="r-host" placeholder="Hostname" style="flex:1">
<select id="r-type"><option>A</option><option>AAAA</option><option>CNAME</option><option>TXT</option><option>MX</option><option>SRV</option><option>PTR</option></select>
<input id="r-ip" placeholder="Value / IP / target" style="flex:1">
<input id="r-note" placeholder="Note" style="flex:1">
<button id="btn-add-rec">Add Record</button>
</div></div></div>
<div class="panel"><h2>Import Zone File</h2><div class="panel-body"><div class="fr">
<input id="import-path" placeholder="D:\Downloads\moreno.land.txt" style="flex:2">
<input id="import-file" type="file" accept=".txt,.zone,.bind,.dns" style="display:none">
<button id="btn-browse-zone" class="ghost">Browse</button>
<input id="import-zone" placeholder="Zone origin, e.g. moreno.land" style="flex:1">
<label class="tog compact"><input id="import-overwrite" type="checkbox"> Overwrite</label>
<button id="btn-import-zone">Import Records</button>
<span id="import-result" class="muted"></span>
</div></div></div>
<div class="panel"><h2>Configured Records</h2>
<table><thead><tr><th>Hostname</th><th>Type</th><th>Value</th><th>Note</th><th></th></tr></thead><tbody id="recs"></tbody></table>
</div>
</div>
<div id="t-blocklist" class="tp">
<div class="page-head"><div class="page-title"><h2>Blocklists</h2><p>Subscribed lists and manual deny rules used by DNSLeaf.</p></div><div class="toolbar"><select id="gravity-target"><option value="">All Lists</option></select><button id="btn-reload-bl">Update Gravity</button></div></div>
<div class="panel"><h2>Manual Denylist</h2><div class="panel-body"><div class="fr">
<select id="blk-context"><option value="custom">Custom</option></select>
<input id="b-dom" placeholder="example.com, *.ads.com, ads*.site.com, regex:^tracker[0-9]+\.com$" style="flex:1">
<button id="btn-add-blk">Block</button>
</div><div class="fr" style="margin-top:10px">
<input id="blk-filter" placeholder="Search blocked domains or source" style="flex:1">
<select id="blk-page-size"><option>25</option><option selected>50</option><option>100</option><option>250</option></select>
<span id="blk-count" class="muted"></span>
</div></div>
<table><thead><tr><th>Domain</th><th>Source</th><th></th></tr></thead><tbody id="blks"></tbody></table>
<div class="panel-body"><div class="fr">
<button id="blk-prev" class="ghost">Previous</button>
<span id="blk-page" class="muted"></span>
<button id="blk-next" class="ghost">Next</button>
</div></div>
</div>
<div class="panel">
<h2>Regex / Wildcard Rules</h2>
<div class="panel-body"><div class="fr"><input id="rx-rule" placeholder="regex:^tracker[0-9]+\.com$ or *.ads.example" style="flex:1"><button id="btn-add-rx">Add Rule</button></div></div>
<table><thead><tr><th>Rule</th><th></th></tr></thead><tbody id="rxs"></tbody></table>
</div>
<div class="panel">
<h2>Groups</h2>
<div class="panel-body">
<div class="fr"><input id="grp-name" placeholder="Group name, e.g. Microsoft" style="flex:1"><textarea id="grp-domains" placeholder="One domain per line" style="flex:2;min-height:70px"></textarea><input id="grp-sources" placeholder="Assigned list source/name, one or comma separated" style="flex:1"><button id="btn-save-group">Save Group</button></div>
</div>
<table><thead><tr><th>Name</th><th>Domains</th><th>Assigned Sources</th><th></th></tr></thead><tbody id="groups"></tbody></table>
</div>
<div class="panel">
<h2>Subscribed Blocklists</h2>
<div class="panel-body"><div class="fr">
<input id="bl-name" placeholder="Name" style="flex:1">
<input id="bl-source" placeholder="Local path or https:// URL" style="flex:2">
<button id="btn-add-list">Add List</button>
</div></div>
<table><thead><tr><th>Name</th><th>Source</th><th>Status</th><th>Loaded</th><th>Refreshed</th><th>Exceptions / Error</th><th></th></tr></thead><tbody id="lists"></tbody></table>
</div>
</div>
<div id="gravity-modal" class="modal"><div class="dialog"><div class="dialog-head"><div><h2>Gravity Update</h2><div class="muted" id="gravity-state">Idle</div></div><button id="gravity-close" class="ghost">Close</button></div><div class="dialog-body"><pre id="gravity-log" class="console"></pre></div></div></div>
<div id="t-upstreams" class="tp">
<div class="page-head">
<div class="page-title"><h2>Upstream Resolvers</h2><p>DNS servers used when a request is not answered locally or blocked.</p></div>
<div class="toolbar">
<input id="u-addr" placeholder="Add resolver, e.g. 1.1.1.1:53" style="flex:1">
<button id="btn-add-up">Add Upstream</button>
</div>
</div>
<div class="panel"><h2>Configured Resolvers</h2>
<table><thead><tr><th>Address</th><th>Status</th><th></th></tr></thead><tbody id="ups"></tbody></table>
</div>
</div>
<div id="t-clients" class="tp">
<div class="page-head"><div class="page-title"><h2>Clients</h2><p>Name devices, assign profiles, review access, and manage resolver whitelist entries.</p></div><div class="toolbar"><button id="btn-clear-denied-clients" class="ghost">Clear Denied</button><button id="btn-load-clients" class="ghost">Refresh</button></div></div>
<div class="panel"><h2>Profile Assignment</h2><div class="panel-body"><div class="fr"><input id="cp-ip" placeholder="Client IP or CIDR, e.g. 192.168.0.25 or 192.168.0.0/24" style="flex:1"><select id="cp-profile"></select><button id="btn-set-client-profile">Assign Profile</button></div></div></div>
<div class="panel"><h2>Known Clients</h2>
<table><thead><tr><th>Name</th><th>IP</th><th>Profile</th><th>LAN</th><th>Allowed</th><th>Queries</th><th>Denied</th><th>Trolled</th><th>Last Seen</th><th></th></tr></thead><tbody id="clients"></tbody></table>
</div>
</div>
<div id="t-profiles" class="tp">
<div class="page-head"><div class="page-title"><h2>Profiles</h2><p>Per-client filtering profiles with blocklist selection, overrides, and safe search.</p></div></div>
<div class="panel"><h2>Create Profile</h2><div class="panel-body"><div class="fr"><input id="pf-name" placeholder="Profile name, e.g. kids" style="flex:1"><button id="btn-add-profile">Create Profile</button></div></div></div>
<div class="panel"><h2>Configured Profiles</h2><table><thead><tr><th>Name</th><th>Mode</th><th>Blocklists</th><th>Allowed Overrides</th><th>Blocked Overrides</th><th></th></tr></thead><tbody id="profiles"></tbody></table></div>
</div>
<div id="t-log" class="tp">
<div class="page-head"><div class="page-title"><h2>Query Log</h2><p>Recent DNS activity, answers, and filtering actions.</p></div><div class="toolbar"><input id="log-filter" placeholder="Filter by domain, client, answer, or action"><button id="btn-clear-log" class="ghost">Clear Log</button></div></div>
<div class="panel"><h2>Recent Queries</h2>
<table class="qlog"><thead><tr><th>Time</th><th>Client</th><th>Transport</th><th>Domain</th><th>Answer</th><th>Type</th><th>Action</th><th>Source</th><th>ms</th><th>Controls</th></tr></thead><tbody id="logs"></tbody></table>
</div>
</div>
<div id="t-settings" class="tp">
<div class="page-head"><div class="page-title"><h2>Settings</h2><p>Runtime DNS behavior, cache policy, and resolver access controls.</p></div></div>
<div class="panel">
<h2>DNS Settings</h2>
<div class="panel-body">
<div class="setting-section">
<div class="setting-title">Bind Addresses</div>
<div class="formgrid">
<div class="field"><label for="set-listen">DNS listen address</label><input id="set-listen" placeholder=":53"><div class="hint">Address and port for DNS over UDP/TCP. Use <code>:53</code> for all interfaces.</div></div>
<div class="field"><label for="set-http">Web panel listen address</label><input id="set-http" placeholder="127.0.0.1:8080"><div class="hint">Keep this on localhost for VPS use, then access it through SSH forwarding.</div></div>
<div class="field"><label for="set-https">HTTPS web listen address</label><input id="set-https" placeholder=":8443"><div class="hint">Optional TLS admin panel address when certificate and key files are set.</div></div>
<div class="field"><label for="set-cert">TLS certificate file</label><input id="set-cert" placeholder="cert.pem"><div class="hint">PEM certificate used by the HTTPS web panel.</div></div>
<div class="field"><label for="set-key">TLS key file</label><input id="set-key" placeholder="key.pem"><div class="hint">PEM private key used by the HTTPS web panel.</div></div>
<div class="field"><label for="set-portal-host">Portal hostname</label><input id="set-portal-host" placeholder="dns.leaf"><div class="hint">Local DNS name that resolves to this DNSLeaf admin server.</div></div>
<div class="field"><label for="set-portal-ip">Portal IP address</label><input id="set-portal-ip" placeholder="127.0.0.1"><div class="hint">IP returned for the portal hostname.</div></div>
</div>
</div>
<div class="setting-section">
<div class="setting-title">Blocklist</div>
<div class="formgrid">
<div class="field"><label for="set-blocklist">Blocklist file</label><input id="set-blocklist" placeholder="blocklist.txt"><div class="hint">Local file loaded by Reload File and on startup.</div></div>
</div>
</div>
<div class="setting-section">
<div class="setting-title">Cache</div>
<div class="formgrid">
<div class="field"><label for="set-cache-size">Cache size</label><input id="set-cache-size" type="number" min="1" placeholder="1000"><div class="hint">Maximum number of DNS answers to keep in memory.</div></div>
<div class="field"><label for="set-cache-ttl">Default cache TTL seconds</label><input id="set-cache-ttl" type="number" min="1" placeholder="300"><div class="hint">Fallback lifetime when an upstream response has no useful TTL.</div></div>
<label class="tog"><input id="set-cache" type="checkbox"> Cache enabled</label>
</div>
</div>
<div class="setting-section">
<div class="setting-title">Access Policy</div>
<div class="formgrid">
<label class="tog"><input id="set-resolver-disabled" type="checkbox"> Disable resolver (pass through to upstream)</label>
<label class="tog"><input id="set-lan" type="checkbox"> Allow LAN clients only</label>
<label class="tog"><input id="set-whitelist-only" type="checkbox"> Whitelist only mode</label>
<label class="tog"><input id="set-direct-override" type="checkbox"> Direct override for denied clients</label>
<label class="tog"><input id="set-troll" type="checkbox"> Troll mode for denied clients</label>
</div>
<div class="fr" style="margin-top:12px">
<div class="field" style="flex:1"><label for="set-whitelist">Allowed IPs / CIDRs</label><input id="set-whitelist" placeholder="203.0.113.10, 198.51.100.0/24"><div class="hint">Used by whitelist-only mode and as exceptions to LAN-only mode.</div></div>
<button id="btn-save-settings">Save Settings</button>
</div>
<div class="formgrid" style="margin-top:12px">
<div class="field"><label for="set-direct-to">Direct override target</label><input id="set-direct-to" placeholder="dns.leaf or 192.168.0.3"><div class="hint">Denied clients receive this record/IP for their DNS requests.</div></div>
<div class="field"><label for="set-troll-hosts">Troll target sites</label><textarea id="set-troll-hosts" placeholder="4chan.org&#10;neopets.com&#10;homestarrunner.com"></textarea><div class="hint">Denied clients receive an IP from a random target site when Troll mode is enabled.</div></div>
</div>
<div class="muted">Whitelist-only mode is best when this runs on a public VPS.</div>
</div>
</div>
</div>
</div>
<div id="t-proxy" class="tp">
<div class="page-head"><div class="page-title"><h2>Proxy</h2><p>Optional HTTP CONNECT and SOCKS5 tunneling with DNSLeaf access policy.</p></div><div class="toolbar"><button id="btn-save-proxy">Save Proxy</button></div></div>
<div class="stats">
<div class="sc"><div class="l">HTTP Proxy</div><div class="v small" id="proxy-http-state">Off</div><span class="wm route"><i></i></span></div>
<div class="sc"><div class="l">SOCKS5 Proxy</div><div class="v small" id="proxy-socks-state">Off</div><span class="wm route"><i></i></span></div>
<div class="sc"><div class="l">Access Policy</div><div class="v small" id="proxy-policy-state">-</div><span class="wm hand"></span></div>
</div>
<div class="grid">
<div class="panel">
<h2>HTTP CONNECT Proxy</h2>
<div class="panel-body">
<div class="formgrid">
<label class="tog"><input id="set-http-proxy-enabled" type="checkbox"> Enable HTTP proxy</label>
<div class="field"><label for="set-http-proxy">Listen address</label><input id="set-http-proxy" placeholder="127.0.0.1:8088"><div class="hint">Use this as the HTTP/HTTPS proxy address in browsers or operating system proxy settings.</div></div>
</div>
<div class="info" style="margin-top:12px"><div class="ii"><div class="k">Client endpoint</div><div class="kv" id="proxy-http-url">disabled</div></div><div class="ii"><div class="k">Protocol</div><div class="kv">HTTP + CONNECT</div></div></div>
</div>
</div>
<div class="panel">
<h2>SOCKS5 Proxy</h2>
<div class="panel-body">
<div class="formgrid">
<label class="tog"><input id="set-socks-proxy-enabled" type="checkbox"> Enable SOCKS5 proxy</label>
<div class="field"><label for="set-socks-proxy">Listen address</label><input id="set-socks-proxy" placeholder="127.0.0.1:1080"><div class="hint">Use this as a SOCKS5 host/port in apps that support SOCKS tunneling.</div></div>
</div>
<div class="info" style="margin-top:12px"><div class="ii"><div class="k">Client endpoint</div><div class="kv" id="proxy-socks-url">disabled</div></div><div class="ii"><div class="k">Protocol</div><div class="kv">SOCKS5 TCP</div></div></div>
</div>
</div>
<div class="panel">
<h2>Guard Rails</h2>
<div class="panel-body"><div class="info"><div class="ii"><div class="k">Allowed clients</div><div class="kv" id="proxy-allowed-state">-</div></div><div class="ii"><div class="k">Denied clients</div><div class="kv">no tunnel</div></div><div class="ii"><div class="k">Logging</div><div class="kv">server log</div></div></div></div>
</div>
</div>
</div>
<div id="t-certs" class="tp">
<div class="page-head"><div class="page-title"><h2>Certificates</h2><p>Create offline TLS certificates for local DNSLeaf names, LAN services, and private domains.</p></div></div>
<div class="panel">
<h2>Self-Signed Certificate Authority / Server Certificate</h2>
<div class="panel-body">
<div class="formgrid">
<div class="field"><label for="cert-cn">Common name</label><input id="cert-cn" placeholder="dns.leaf"><div class="hint">Primary name shown on the certificate. Browsers validate SANs, not only this field.</div></div>
<div class="field"><label for="cert-dns">DNS subject alternative names</label><textarea id="cert-dns" placeholder="dns.leaf&#10;local.modem&#10;*.home.arpa"></textarea><div class="hint">One per line or comma-separated. Include every hostname that should pass TLS name validation.</div></div>
<div class="field"><label for="cert-ips">IP subject alternative names</label><textarea id="cert-ips" placeholder="127.0.0.1&#10;192.168.0.1"></textarea><div class="hint">One per line or comma-separated. Required when browsing by IP address.</div></div>
<div class="field"><label for="cert-org">Organization</label><input id="cert-org" placeholder="DNSLeaf local"><div class="hint">Optional certificate subject organization.</div></div>
<div class="field"><label for="cert-days">Validity days</label><input id="cert-days" type="number" min="1" max="3650" placeholder="398"><div class="hint">398 days is a modern browser-friendly default for server certificates.</div></div>
<div class="field"><label for="cert-key-type">Key type</label><select id="cert-key-type"><option value="ecdsa-p256">ECDSA P-256</option><option value="rsa-2048">RSA 2048</option><option value="rsa-3072">RSA 3072</option><option value="rsa-4096">RSA 4096</option></select><div class="hint">ECDSA P-256 is small, modern, and fast. RSA is available for older clients.</div></div>
<div class="field"><label for="cert-cert-path">Certificate output file</label><input id="cert-cert-path" placeholder="certs/dnsleaf-cert.pem"><div class="hint">PEM certificate path written on this server.</div></div>
<div class="field"><label for="cert-key-path">Private key output file</label><input id="cert-key-path" placeholder="certs/dnsleaf-key.pem"><div class="hint">PEM private key path. Keep this file private.</div></div>
</div>
<div class="fr" style="margin-top:12px">
<label class="tog compact"><input id="cert-is-ca" type="checkbox"> Create CA certificate</label>
<label class="tog compact"><input id="cert-apply" type="checkbox" checked> Use for DNSLeaf HTTPS panel</label>
<input id="cert-https" placeholder="HTTPS listen address, e.g. :8443" style="max-width:260px">
<button id="btn-create-cert">Create Certificate</button>
</div>
<div id="cert-result" class="muted" style="margin-top:12px"></div>
</div>
</div>
<div class="panel">
<h2>Certificate Notes</h2>
<div class="panel-body muted">
Self-signed certificates are encrypted and standards-shaped, but browsers will not trust them until you install the certificate or CA certificate into the client trust store. For public internet sites, use a public CA certificate when possible. For offline LAN use, create a CA certificate, trust that CA on your devices, then issue local server certificates from it in a future pass.
</div>
</div>
</div>
<div id="t-serverlog" class="tp">
<div class="page-head"><div class="page-title"><h2>Server Log</h2><p>DNSLeaf runtime messages, listener events, and HTTP/TLS server errors.</p></div><div class="toolbar"><button id="btn-refresh-serverlog" class="ghost">Refresh</button><button id="btn-clear-serverlog" class="ghost">Clear Log</button></div></div>
<div class="panel"><h2>Runtime Events</h2><div class="panel-body"><pre id="serverlog" style="white-space:pre-wrap;font-family:Consolas,'Courier New',monospace;line-height:1.45;color:#edf3f6;min-height:360px"></pre></div></div>
</div>
<div id="t-users" class="tp">
<div class="page-head"><div class="page-title"><h2>Users</h2><p>Panel accounts and permission roles.</p></div></div>
<div class="panel">
<h2>Panel Users</h2>
<div class="panel-body"><div class="fr">
<input id="new-user" placeholder="Username">
<input id="new-pass" type="password" placeholder="Password">
<select id="new-role"><option value="viewer">Viewer</option><option value="admin">Admin</option></select>
<button id="btn-add-user">Add User</button>
</div></div>
<table><thead><tr><th>User</th><th>Role</th><th>Created</th><th>Reset Password</th><th></th></tr></thead><tbody id="users"></tbody></table>
</div>
</div>
</main>
<div id="toasts" class="toast-wrap"></div>
<script>
var cur='dashboard',li,me={role:'viewer'},blkRows=[],blkPage=1,listsCache=[],groupsCache=[],listEntryCache={},profileCache={},defaultProfile='default',gravityTimer=null;
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function toast(msg,type){var wrap=document.getElementById('toasts'),el=document.createElement('div');el.className='toast '+(type||'');el.textContent=msg;wrap.appendChild(el);setTimeout(function(){el.style.opacity='0';el.style.transform='translateY(6px)';},2600);setTimeout(function(){el.remove();},3200)}
function api(m,p,b){var o={method:m,headers:{'Content-Type':'application/json','X-DNSLeaf-Request':'1'}};if(b)o.body=JSON.stringify(b);return fetch(p,o).then(function(r){if(r.status===401){showLogin();return null;}if(r.status===204)return null;if(!r.ok)throw new Error(r.status);return r.json()}).catch(function(){toast('Request failed: '+p,'err');return null})}
function showLogin(){document.getElementById('auth').classList.remove('hide');}
function hideLogin(){document.getElementById('auth').classList.add('hide');}
function loadRememberedLogin(){
 try{
  var u=localStorage.getItem('dnsleaf_user')||'';
  if(u){document.getElementById('login-user').value=u;document.getElementById('remember-user').checked=true;}
 }catch(e){}
}
function saveRememberedLogin(){
 try{
  var u=document.getElementById('login-user').value;
  if(document.getElementById('remember-user').checked)localStorage.setItem('dnsleaf_user',u);else localStorage.removeItem('dnsleaf_user');
  localStorage.removeItem('dnsleaf_pass');
 }catch(e){}
}
function checkSession(){
 api('GET','/api/session').then(function(s){
  if(!s||!s.authenticated){showLogin();return;}
  me=s;hideLogin();
  document.getElementById('account-user').textContent=s.username;
  if(s.role!=='admin')document.querySelector('[data-t="users"]').style.display='none';
  loadSt();
 });
}
function login(){
 var u=document.getElementById('login-user').value,p=document.getElementById('login-pass').value;
 api('POST','/api/login',{username:u,password:p}).then(function(s){
 if(!s||!s.authenticated){document.getElementById('login-error').textContent='Invalid username or password';return;}
 saveRememberedLogin();
  document.getElementById('login-pass').value='';
  checkSession();
 });
}
function logout(){api('DELETE','/api/login').then(function(){showLogin();});}
function sw(t){
 if(!t)return;
 document.querySelectorAll('.tp').forEach(function(e){e.classList.remove('on')});
 document.querySelectorAll('#tabs a[data-t]').forEach(function(e){e.classList.remove('on')});
 document.getElementById('t-'+t).classList.add('on');
 document.querySelector('[data-t="'+t+'"]').classList.add('on');
 location.hash=t;
 cur=t;clearInterval(li);
 if(t==='dashboard')loadSt();
 if(t==='records')loadRec();
 if(t==='blocklist')loadBlk();
 if(t==='profiles')loadProfiles();
 if(t==='upstreams')loadUp();
 if(t==='clients'){loadProfiles(loadClients);}
	if(t==='log'){loadLg();li=setInterval(loadLg,2000);}
	if(t==='settings')loadSettings();
	if(t==='certs')loadCertPage();
	if(t==='proxy')loadSettings();
	if(t==='serverlog')loadServerLog();
	if(t==='users')loadUsers();
}
function drawChart(s){
 var vals=[['Blocked',s.blocked,'#ff6363'],['Local',s.local,'#32d583'],['Cached',s.cached,'#f4bf50'],['Forwarded',s.forwarded,'#4da3ff']];
 var max=Math.max(1,s.blocked,s.local,s.cached,s.forwarded), total=Math.max(1,s.blocked+s.local+s.cached+s.forwarded), h='';
 var p1=s.forwarded/total*100,p2=p1+s.cached/total*100,p3=p2+s.local/total*100;
 h='<div class="mix-donut" style="--fwd:'+p1+'%;--cache:'+p2+'%;--local:'+p3+'%"><div class="mix-total">'+total+'<span>queries</span></div></div><div class="mix-legend">';
 vals.forEach(function(v){
  var pct=Math.max(1,Math.round(v[1]/max*100));
  h+='<div class="mix-row"><div class="mix-dot" style="background:'+v[2]+'"></div><div class="mix-name">'+v[0]+'</div><div class="mix-track"><div class="mix-fill" style="width:'+pct+'%;background:'+v[2]+'"></div></div><div class="mix-val">'+v[1]+'</div></div>';
 });
 h+='</div>';
 document.getElementById('chart').innerHTML=h;
}
function drawActivity(){
 api('GET','/api/log').then(function(d){
  var el=document.getElementById('activity');if(!el)return;
  if(!d||!d.length){el.innerHTML='<div class="empty" style="grid-column:1 / -1;width:100%">No query activity yet</div>';return;}
  var count=30, step=60*1000, now=Date.now(), end=Math.ceil(now/step)*step, start=end-count*step, buckets=[];
  for(var i=0;i<count;i++){
   var t=start+i*step, dt=new Date(t);
   buckets.push({total:0,blocked:0,local:0,cached:0,forwarded:0,label:String(dt.getHours()).padStart(2,'0')+':'+String(dt.getMinutes()).padStart(2,'0')});
  }
  d.forEach(function(e){
   var ts=Number(e.ts||0);if(!ts||ts<start||ts>=end)return;
   var b=Math.floor((ts-start)/step);if(b<0||b>=count)return;
   var a=(e.action||'forwarded').toLowerCase();buckets[b].total++;
   if(a==='blocked'||a==='denied')buckets[b].blocked++;
   else if(a==='local')buckets[b].local++;
   else if(a==='cached')buckets[b].cached++;
   else buckets[b].forwarded++;
  });
  var realTotal=buckets.reduce(function(n,b){return n+b.total;},0);
  if(!realTotal){el.innerHTML='<div class="empty" style="grid-column:1 / -1;width:100%">No query activity in the last 30 minutes</div>';return;}
  var max=Math.max.apply(null,buckets.map(function(b){return b.total;}));if(max<1)max=1;
  var top=Math.max(5,Math.ceil(max/5)*5), ticks=[], bars='', labels='';
  for(var t=5;t>=0;t--)ticks.push('<span>'+Math.round(top*t/5)+'</span>');
  buckets.forEach(function(b,i){
   var h=b.total?Math.max(3,Math.round(b.total/top*285)):0, title=b.total+' queries';
   var segs='', keys=['forwarded','cached','local','blocked'];
   keys.forEach(function(k){if(b[k]>0){segs+='<div class="spark-seg '+k+'" style="height:'+Math.max(2,Math.round(b[k]/b.total*100))+'%"></div>'; }});
   bars+='<div class="spark-col '+(b.total?'has':'')+'" title="'+title+'" style="--h:'+h+'px">'+segs+'</div>';
   labels+=(i%5===0)?'<span>'+esc(b.label)+'</span>':'<span></span>';
  });
  var cols='repeat('+count+',minmax(4px,1fr))';
  el.innerHTML='<div class="spark-ytitle">Queries</div><div class="spark-axis">'+ticks.join('')+'</div><div class="spark-plot" style="grid-template-columns:'+cols+'">'+bars+'</div><div class="spark-xaxis" style="grid-template-columns:'+cols+'">'+labels+'</div><div class="spark-xtitle">Time - last 30 minutes</div>';
 });
}
function loadSt(){
 api('GET','/api/status').then(function(d){
  if(!d)return;
  document.getElementById('s-q').textContent=d.stats.total_queries;
  document.getElementById('s-b').textContent=d.stats.blocked;
  document.getElementById('s-l').textContent=d.stats.local;
  document.getElementById('s-c').textContent=d.stats.cached;
  document.getElementById('s-f').textContent=d.stats.forwarded;
  document.getElementById('s-d').textContent=d.blocked_count;
  document.getElementById('svc-status').textContent=d.resolver_disabled?'Resolver disabled - pass through':(d.whitelist_only?'Whitelist protected':(d.lan_only?'Private resolver':'Resolver active'));
  if(d.host){document.getElementById('host-uptime').textContent=d.uptime||'-';document.getElementById('host-cpu').textContent=d.host.cpu||'-';document.getElementById('host-mem').textContent=d.host.memory||'-';}
  document.getElementById('info').innerHTML=
   '<div class="ii"><div class="k">Uptime</div><div class="kv">'+esc(d.uptime)+'</div></div>'+
   '<div class="ii"><div class="k">Upstreams</div><div class="kv">'+d.active_upstreams+' / '+d.upstream_count+' active</div></div>'+
   '<div class="ii"><div class="k">Local Records</div><div class="kv">'+d.records_count+'</div></div>'+
   '<div class="ii"><div class="k">Known Clients</div><div class="kv">'+d.client_count+'</div></div>'+
   '<div class="ii"><div class="k">DNS Listen</div><div class="kv">'+esc(d.listen)+'</div></div>'+
   '<div class="ii"><div class="k">Resolver</div><div class="kv">'+(d.resolver_disabled?'disabled - pass through':'active')+'</div></div>'+
   '<div class="ii"><div class="k">Access Policy</div><div class="kv">'+(d.whitelist_only?'whitelist protected':(d.lan_only?'private networks':'open resolver'))+'</div></div>'+
   '<div class="ii"><div class="k">Cache</div><div class="kv">'+(d.cache_enabled?'on':'off')+'</div></div>';
  drawChart(d.stats);
  drawActivity();
  loadDashClients();
 });
}
function loadRec(){
 api('GET','/api/records').then(function(d){
  var tb=document.getElementById('recs');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="5" class="empty">No local records configured</td></tr>';return;}
  tb.innerHTML=d.map(function(r){
   var typ=(r.type||(/:/.test(r.ip||'')?'AAAA':'A')).toUpperCase(),val=r.value||r.ip||'';
   return '<tr><td><input value="'+esc(r.host)+'" data-old-host="'+esc(r.host)+'" data-old-ip="'+esc(r.ip||val)+'" class="rec-host"></td><td><select class="rec-type"><option '+(typ==='A'?'selected':'')+'>A</option><option '+(typ==='AAAA'?'selected':'')+'>AAAA</option><option '+(typ==='CNAME'?'selected':'')+'>CNAME</option><option '+(typ==='TXT'?'selected':'')+'>TXT</option><option '+(typ==='MX'?'selected':'')+'>MX</option><option '+(typ==='SRV'?'selected':'')+'>SRV</option><option '+(typ==='PTR'?'selected':'')+'>PTR</option></select></td><td><input value="'+esc(val)+'" class="rec-ip"></td><td><input value="'+esc(r.note||'')+'" class="rec-note" placeholder="Note"></td><td><button class="sm ok" onclick="saveRec(this)">Save</button> <button class="sm dg" data-ip="'+esc(r.ip||val)+'" data-host="'+esc(r.host)+'" onclick="delRec(this)">Remove</button></td></tr>';
  }).join('');
 });
}
function addRec(){
 var h=document.getElementById('r-host').value,i=document.getElementById('r-ip').value,t=document.getElementById('r-type').value,n=document.getElementById('r-note').value;
 if(!h||!i)return;
 api('POST','/api/records',{host:h,type:t,value:i,ip:i,note:n}).then(function(){document.getElementById('r-host').value='';document.getElementById('r-ip').value='';document.getElementById('r-note').value='';loadRec();});
}
function saveRec(btn){
 var tr=btn.closest('tr'),h=tr.querySelector('.rec-host'),i=tr.querySelector('.rec-ip');
 api('PUT','/api/records',{old_host:h.dataset.oldHost,old_ip:h.dataset.oldIp,host:h.value,type:tr.querySelector('.rec-type').value,value:i.value,ip:i.value,note:tr.querySelector('.rec-note').value}).then(loadRec);
}
function delRec(el){api('DELETE','/api/records',{ip:el.dataset.ip,host:el.dataset.host}).then(loadRec);}
function importZone(){
 var p=document.getElementById('import-path').value,z=document.getElementById('import-zone').value,f=document.getElementById('import-file').files[0];
 if(f){
  var fd=new FormData();
  fd.append('file',f);fd.append('zone',z);fd.append('overwrite',document.getElementById('import-overwrite').checked?'true':'false');
  fetch('/api/records/import',{method:'POST',headers:{'X-DNSLeaf-Request':'1'},body:fd}).then(function(r){if(!r.ok)throw new Error(r.status);return r.json();}).then(function(r){
   document.getElementById('import-result').textContent='Imported '+r.imported+', skipped '+r.skipped;
   document.getElementById('import-file').value='';
   loadRec();
  }).catch(function(){toast('Zone import failed','err');});
  return;
 }
 if(!p)return;
 api('POST','/api/records/import',{path:p,zone:z,overwrite:document.getElementById('import-overwrite').checked}).then(function(r){
  document.getElementById('import-result').textContent=r?('Imported '+r.imported+', skipped '+r.skipped):'Import failed';
  loadRec();
 });
}
function browseZone(){document.getElementById('import-file').click();}
function pickedZone(){
 var f=document.getElementById('import-file').files[0];
 if(f)document.getElementById('import-path').value=f.name;
}
function loadBlk(){
 loadLists();
 loadGroups();
 loadRegex();
 api('GET','/api/blocked').then(function(d){
  blkRows=(d||[]).sort(function(a,b){return (a.domain||'').localeCompare(b.domain||'')});
  blkPage=1;
  renderBlk();
 });
}
function contextRows(){
 var ctx=document.getElementById('blk-context').value||'custom';
 if(ctx.indexOf('list:')===0){
  var src=ctx.slice(5),list=listsCache.find(function(l){return l.source===src;});
  if(!listEntryCache[src]){loadListEntries(src);return {kind:'list',title:list?(list.name||list.source):src,total:0,rows:[],loading:true};}
  return {kind:'list',title:list?(list.name||list.source):src,total:listEntryCache[src].length,rows:listEntryCache[src]};
 }
 if(ctx.indexOf('group:')===0){
  var name=ctx.slice(6),group=groupsCache.find(function(g){return g.name===name;});
  return {kind:'group',title:name,total:(group&&group.domains||[]).length,rows:(group&&group.domains||[]).map(function(d){return {domain:d,source:'group: '+name}})};
 }
 return {kind:'custom',title:'Custom',total:blkRows.length,rows:blkRows};
}
function renderBlk(){
 var tb=document.getElementById('blks'),filter=(document.getElementById('blk-filter')&&document.getElementById('blk-filter').value||'').toLowerCase();
 var size=parseInt(document.getElementById('blk-page-size').value,10)||50;
 var ctx=contextRows();
 var rows=ctx.rows.filter(function(b){return !filter||[b.domain,b.source].join(' ').toLowerCase().indexOf(filter)>=0;});
 var pages=Math.max(1,Math.ceil(rows.length/size));if(blkPage>pages)blkPage=pages;if(blkPage<1)blkPage=1;
 document.getElementById('blk-count').textContent=ctx.title+': '+rows.length+' shown / '+ctx.total+' total';
 document.getElementById('blk-page').textContent='Page '+blkPage+' of '+pages;
 document.getElementById('blk-prev').disabled=blkPage<=1;document.getElementById('blk-next').disabled=blkPage>=pages;
 if(!rows.length){tb.innerHTML='<tr><td colspan="3" class="empty">No blocked domains</td></tr>';return;}
 tb.innerHTML=rows.slice((blkPage-1)*size,blkPage*size).map(function(b){
   var ctl=ctx.kind==='list'?'<span class="muted">source managed</span>':'<button class="sm dg" data-domain="'+esc(b.domain)+'" onclick="delBlk(this)">Remove</button>';
   return '<tr><td><code>'+esc(b.domain)+'</code></td><td>'+esc(b.source)+'</td><td>'+ctl+'</td></tr>';
  }).join('');
}
function loadListEntries(src){
 listEntryCache[src]=[];
 api('GET','/api/blocklists/entries?source='+encodeURIComponent(src)).then(function(d){
  listEntryCache[src]=(d||[]).sort(function(a,b){return (a.domain||'').localeCompare(b.domain||'')});
  renderBlk();
 });
}
function addBlk(){
 var d=document.getElementById('b-dom').value;if(!d)return;
 var ctx=document.getElementById('blk-context').value||'custom';
 if(ctx.indexOf('list:')===0){
  toast('Subscribed lists are read-only here. Use Custom denylist or Groups to add manual blocks.','err');
  return;
 }
 if(ctx.indexOf('group:')===0){
  var name=ctx.slice(6),group=groupsCache.find(function(g){return g.name===name;});if(!group)return;
  group.domains=(group.domains||[]).concat(d.split(/[,\n]/).map(function(x){return x.trim();}).filter(Boolean));
  api('POST','/api/block-groups',group).then(function(){document.getElementById('b-dom').value='';loadBlk();toast('Group updated','ok');});
  return;
 }
 api('POST','/api/blocked',{domain:d}).then(function(){document.getElementById('b-dom').value='';loadBlk();toast('Domain blocked','ok');});
}
function delBlk(el){
 var ctx=document.getElementById('blk-context').value||'custom',dom=el.dataset.domain;
 if(ctx.indexOf('list:')===0){
  toast('Subscribed list entries are managed by the source list. Add an exception in the Subscribed Blocklists table.','err');
  return;
 }
 if(ctx.indexOf('group:')===0){
  var name=ctx.slice(6),group=groupsCache.find(function(g){return g.name===name;});if(!group)return;
  group.domains=(group.domains||[]).filter(function(x){return x!==dom;});
  api('POST','/api/block-groups',group).then(function(){loadBlk();toast('Group updated','ok');});
  return;
 }
 api('DELETE','/api/blocked',{domain:dom}).then(function(){loadBlk();toast('Domain removed','ok');});
}
function loadLists(){
 api('GET','/api/blocklists').then(function(d){
  listsCache=d||[];
  renderBlockContextOptions();
  renderGravityOptions();
  var tb=document.getElementById('lists');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="7" class="empty">No subscribed blocklists</td></tr>';return;}
  tb.innerHTML=d.map(function(l,i){
   return '<tr><td><input value="'+esc(l.name||'')+'" class="list-name"></td><td><code>'+esc(l.source)+'</code></td><td><span class="tag '+(l.enabled?'tag-on':'tag-off')+'">'+(l.enabled?'enabled':'disabled')+'</span></td><td>'+((l.last_loaded||0))+'</td><td>'+esc(l.last_refreshed||'-')+'</td><td><textarea class="list-allow" placeholder="One exception per line">'+esc((l.allowlist||[]).join('\n'))+'</textarea><input class="list-groups" placeholder="Assigned groups, comma separated" value="'+esc((l.groups||[]).join(', '))+'"><div class="muted">'+esc(l.last_error||'')+'</div></td><td><button class="sm ok" data-source="'+esc(l.source)+'" onclick="saveList(this)">Save</button> <button class="sm ghost" data-source="'+esc(l.source)+'" onclick="refreshList(this)">Refresh</button> <button class="sm ghost" data-source="'+esc(l.source)+'" data-enabled="'+l.enabled+'" onclick="togList(this)">'+(l.enabled?'Disable':'Enable')+'</button> <button class="sm dg" data-source="'+esc(l.source)+'" onclick="delList(this)">Remove</button></td></tr>';
  }).join('');
 });
}
function renderBlockContextOptions(){
 var sel=document.getElementById('blk-context'),curv=sel.value||'custom',opts=['<option value="custom">Custom denylist</option>'];
 if(listsCache.length){
  opts.push('<optgroup label="Subscribed blocklists">');
  listsCache.forEach(function(l){opts.push('<option value="list:'+esc(l.source)+'">'+esc(l.name||l.source)+'</option>')});
  opts.push('</optgroup>');
 }
 if(groupsCache.length){
  opts.push('<optgroup label="Groups">');
  groupsCache.forEach(function(g){opts.push('<option value="group:'+esc(g.name)+'">'+esc(g.name)+'</option>')});
  opts.push('</optgroup>');
 }
 sel.innerHTML=opts.join('');
 if([].slice.call(sel.options).some(function(o){return o.value===curv}))sel.value=curv;
 renderBlk();
}
function renderGravityOptions(){
 var sel=document.getElementById('gravity-target'),curv=sel.value||'',opts=['<option value="">All Lists</option>'];
 listsCache.forEach(function(l){opts.push('<option value="'+esc(l.source)+'">'+esc(l.name||l.source)+'</option>')});
 sel.innerHTML=opts.join('');
 if([].slice.call(sel.options).some(function(o){return o.value===curv}))sel.value=curv;
}
function loadGroups(){
 api('GET','/api/block-groups').then(function(d){groupsCache=d||[];renderGroups();renderBlockContextOptions();});
}
function renderGroups(){
 var tb=document.getElementById('groups');if(!tb)return;
 if(!groupsCache.length){tb.innerHTML='<tr><td colspan="4" class="empty">No groups configured</td></tr>';return;}
 tb.innerHTML=groupsCache.map(function(g){
  return '<tr><td><input class="grp-row-name" value="'+esc(g.name)+'" data-old="'+esc(g.name)+'"></td><td><textarea class="grp-row-domains">'+esc((g.domains||[]).join('\n'))+'</textarea></td><td><textarea class="grp-row-sources">'+esc((g.sources||[]).join('\n'))+'</textarea></td><td><button class="sm ok" onclick="saveGroupRow(this)">Save</button> <button class="sm dg" data-name="'+esc(g.name)+'" onclick="delGroup(this)">Remove</button></td></tr>';
 }).join('');
}
function splitLines(v){return (v||'').split(/[,\n]/).map(function(x){return x.trim();}).filter(Boolean);}
function saveGroup(){
 var name=document.getElementById('grp-name').value.trim();if(!name)return;
 api('POST','/api/block-groups',{name:name,domains:splitLines(document.getElementById('grp-domains').value),sources:splitLines(document.getElementById('grp-sources').value)}).then(function(){document.getElementById('grp-name').value='';document.getElementById('grp-domains').value='';document.getElementById('grp-sources').value='';loadBlk();toast('Group saved','ok');});
}
function saveGroupRow(btn){
 var tr=btn.closest('tr'),name=tr.querySelector('.grp-row-name').value.trim(),old=tr.querySelector('.grp-row-name').dataset.old;
 api('POST','/api/block-groups',{old_name:old,name:name,domains:splitLines(tr.querySelector('.grp-row-domains').value),sources:splitLines(tr.querySelector('.grp-row-sources').value)}).then(function(){loadBlk();toast('Group saved','ok');});
}
function delGroup(btn){api('DELETE','/api/block-groups',{name:btn.dataset.name}).then(function(){loadBlk();toast('Group removed','ok');});}
function loadRegex(){
 api('GET','/api/regex-rules').then(function(d){
  var tb=document.getElementById('rxs');if(!tb)return;
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="2" class="empty">No regex or wildcard rules</td></tr>';return;}
  tb.innerHTML=d.map(function(r){return '<tr><td><code>'+esc(r)+'</code></td><td><button class="sm dg" data-rule="'+esc(r)+'" onclick="delRegex(this)">Remove</button></td></tr>';}).join('');
 });
}
function addRegex(){
 var r=document.getElementById('rx-rule').value;if(!r)return;
 api('POST','/api/regex-rules',{rule:r}).then(function(){document.getElementById('rx-rule').value='';loadRegex();loadBlk();});
}
function delRegex(btn){api('DELETE','/api/regex-rules',{rule:btn.dataset.rule}).then(function(){loadRegex();loadBlk();});}
function addList(){
 var n=document.getElementById('bl-name').value,s=document.getElementById('bl-source').value;if(!s)return;
	api('POST','/api/blocklists',{name:n,source:s}).then(function(){document.getElementById('bl-name').value='';document.getElementById('bl-source').value='';loadBlk();loadSt();toast('Blocklist updated','ok');});
}
function listAllow(tr){return splitLines(tr.querySelector('.list-allow').value);}
function listGroups(tr){return splitLines(tr.querySelector('.list-groups').value);}
function saveList(btn){var tr=btn.closest('tr');api('PATCH','/api/blocklists',{source:btn.dataset.source,name:tr.querySelector('.list-name').value,enabled:tr.querySelector('.tag').textContent==='enabled',allowlist:listAllow(tr),groups:listGroups(tr)}).then(function(){loadBlk();loadSt();toast('Blocklist saved','ok');});}
function refreshList(btn){startGravity(btn.dataset.source);}
function togList(btn){api('PATCH','/api/blocklists',{source:btn.dataset.source,enabled:btn.dataset.enabled!=='true'}).then(function(){loadBlk();loadSt();toast('Blocklist updated','ok');});}
function delList(btn){api('DELETE','/api/blocklists',{source:btn.dataset.source}).then(function(){loadBlk();loadSt();toast('Blocklist removed','ok');});}
function startGravity(target){
 document.getElementById('gravity-modal').classList.add('show');
 document.getElementById('gravity-log').textContent='starting...\n';
 api('POST','/api/gravity/start',{target:target||''}).then(function(){pollGravity(true);});
}
function pollGravity(force){
 if(gravityTimer&&!force)return;
 api('GET','/api/gravity/progress').then(function(p){
  if(!p)return;
  document.getElementById('gravity-state').textContent=(p.running?'Running':'Idle')+(p.target?' - '+p.target:'')+(p.error?' - '+p.error:'');
  document.getElementById('gravity-log').textContent=(p.lines||[]).join('\n')||'No gravity activity yet.';
  document.getElementById('gravity-log').scrollTop=document.getElementById('gravity-log').scrollHeight;
  if(p.running){
   gravityTimer=setTimeout(function(){gravityTimer=null;pollGravity(true);},900);
  }else{
   gravityTimer=null;
   loadBlk();loadSt();
  }
 });
}
function loadUp(){
 api('GET','/api/upstreams').then(function(d){
  var tb=document.getElementById('ups');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="3" class="empty">No upstreams - DNS forwarding disabled</td></tr>';return;}
  tb.innerHTML=d.map(function(u){
   return '<tr><td><code>'+esc(u.address)+'</code></td><td><span class="tag '+(u.enabled?'tag-on':'tag-off')+'">'+(u.enabled?'enabled':'disabled')+'</span></td><td><button class="sm ghost" data-addr="'+esc(u.address)+'" data-enabled="'+u.enabled+'" onclick="togUp(this)">'+(u.enabled?'Disable':'Enable')+'</button> <button class="sm dg" data-addr="'+esc(u.address)+'" onclick="delUp(this)">Remove</button></td></tr>';
  }).join('');
 });
}
function addUp(){
 var a=document.getElementById('u-addr').value;if(!a)return;
 api('POST','/api/upstreams',{address:a}).then(function(){document.getElementById('u-addr').value='';loadUp();});
}
function togUp(el){api('PATCH','/api/upstreams',{address:el.dataset.addr,enabled:el.dataset.enabled!=='true'}).then(loadUp);}
function delUp(el){api('DELETE','/api/upstreams',{address:el.dataset.addr}).then(loadUp);}
function profileOptions(selected){
 var names=Object.keys(profileCache).sort(),h='<option value="">Default ('+esc(defaultProfile)+')</option>';
 names.forEach(function(n){h+='<option value="'+esc(n)+'" '+(selected===n?'selected':'')+'>'+esc(n)+'</option>';});
 return h;
}
function blocklistChecks(selected){
 selected=selected||[];
 return listsCache.map(function(l){
  var name=l.name||l.source,on=selected.indexOf(name)>=0||selected.indexOf(l.source)>=0;
  return '<label class="tog compact"><input type="checkbox" class="pf-list" value="'+esc(name)+'" '+(on?'checked':'')+'> '+esc(name)+'</label>';
 }).join('');
}
function loadProfiles(done){
 api('GET','/api/profiles').then(function(d){
  if(!d)return;
  profileCache=d.profiles||{};
  defaultProfile=d.default_profile||'default';
  var finish=function(){renderProfileSelectors();renderProfiles();if(done)done();};
  if(!listsCache.length){api('GET','/api/blocklists').then(function(l){listsCache=l||[];finish();});}else finish();
 });
}
function renderProfileSelectors(){
 var sel=document.getElementById('cp-profile');if(sel)sel.innerHTML=profileOptions('');
}
function renderProfiles(){
 var tb=document.getElementById('profiles');if(!tb)return;
 var names=Object.keys(profileCache).sort();
 if(!names.length){tb.innerHTML='<tr><td colspan="6" class="empty">No profiles configured</td></tr>';return;}
 tb.innerHTML=names.map(function(name){
  var p=profileCache[name]||{},built=(name==='default'||name==='off');
  return '<tr><td><input class="pf-row-name" value="'+esc(name)+'" data-old="'+esc(name)+'" '+(built?'readonly':'')+'></td><td><label class="tog compact"><input class="pf-disable" type="checkbox" '+(p.disable_blocking?'checked':'')+'> Disable blocking</label><label class="tog compact"><input class="pf-safe" type="checkbox" '+(p.safe_search?'checked':'')+'> Safe search</label><label class="tog compact"><input class="pf-default" type="radio" name="pf-default" '+(name===defaultProfile?'checked':'')+'> Default</label></td><td><div class="profile-lists">'+blocklistChecks(p.blocklists||[])+'</div></td><td><textarea class="pf-allow" placeholder="One allowed domain per line">'+esc((p.allowed||[]).join('\n'))+'</textarea></td><td><textarea class="pf-block" placeholder="One blocked domain per line">'+esc((p.blocked||[]).join('\n'))+'</textarea></td><td><button class="sm ok" onclick="saveProfileRow(this)">Save</button> '+(built?'':'<button class="sm dg" data-name="'+esc(name)+'" onclick="delProfile(this)">Remove</button>')+'</td></tr>';
 }).join('');
}
function profileFromRow(tr){
 var old=tr.querySelector('.pf-row-name').dataset.old,name=tr.querySelector('.pf-row-name').value.trim();
 return {old_name:old,name:name,default_profile:tr.querySelector('.pf-default').checked,profile:{disable_blocking:tr.querySelector('.pf-disable').checked,safe_search:tr.querySelector('.pf-safe').checked,blocklists:[].slice.call(tr.querySelectorAll('.pf-list:checked')).map(function(x){return x.value;}),allowed:splitLines(tr.querySelector('.pf-allow').value),blocked:splitLines(tr.querySelector('.pf-block').value)}};
}
function addProfile(){
 var name=document.getElementById('pf-name').value.trim();if(!name)return;
 api('POST','/api/profiles',{name:name,profile:{blocked:[],allowed:[]}}).then(function(){document.getElementById('pf-name').value='';loadProfiles();toast('Profile created','ok');});
}
function saveProfileRow(btn){api('POST','/api/profiles',profileFromRow(btn.closest('tr'))).then(function(){loadProfiles();toast('Profile saved','ok');});}
function delProfile(btn){api('DELETE','/api/profiles/'+encodeURIComponent(btn.dataset.name)).then(function(){loadProfiles();toast('Profile removed','ok');});}
function assignClientProfile(){
 var ip=document.getElementById('cp-ip').value.trim(),profile=document.getElementById('cp-profile').value;
 if(!ip)return;
 api('POST','/api/clients/'+encodeURIComponent(ip)+'/profile',{profile:profile}).then(function(){document.getElementById('cp-ip').value='';loadClients();toast('Client profile assigned','ok');});
}
function loadClients(){
 api('GET','/api/clients').then(function(d){
  var tb=document.getElementById('clients');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="10" class="empty">No clients have queried DNSLeaf yet</td></tr>';return;}
  tb.innerHTML=d.sort(function(a,b){return b.queries-a.queries}).map(function(c){
   return '<tr><td><input value="'+esc(c.name||'')+'" placeholder="Name" class="c-name"></td><td><code>'+esc(c.ip)+'</code></td><td><select class="c-profile">'+profileOptions(c.profile||'')+'</select></td><td>'+(c.lan?'yes':'no')+'</td><td><span class="tag '+(c.allowed?'tag-on':'tag-denied')+'">'+(c.allowed?'allowed':'denied')+'</span></td><td>'+c.queries+'</td><td>'+((c.denied||0))+'</td><td>'+((c.trolled||0))+'</td><td>'+esc(c.last_seen)+'</td><td><button class="sm ok" data-ip="'+esc(c.ip)+'" data-white="'+c.whitelisted+'" onclick="saveClient(this)">Save</button> <button class="sm ghost" data-ip="'+esc(c.ip)+'" data-white="'+c.whitelisted+'" onclick="whiteClient(this)">'+(c.whitelisted?'Unwhitelist':'Whitelist')+'</button> <button class="sm dg" data-ip="'+esc(c.ip)+'" onclick="deleteClient(this)">Remove</button></td></tr>';
  }).join('');
 });
}
function loadDashClients(){
 api('GET','/api/clients').then(function(d){
  var tb=document.getElementById('dash-clients');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="3" class="empty">No clients yet</td></tr>';return;}
  tb.innerHTML=d.sort(function(a,b){return b.queries-a.queries}).slice(0,6).map(function(c){
   return '<tr><td>'+esc(c.name||'Unknown')+'</td><td><code>'+esc(c.ip)+'</code></td><td>'+c.queries+'</td></tr>';
  }).join('');
 });
}
function saveClient(btn){
 var tr=btn.closest('tr'),name=tr.querySelector('.c-name').value;
 api('PATCH','/api/clients',{ip:btn.dataset.ip,name:name,profile:tr.querySelector('.c-profile').value}).then(loadClients);
}
function whiteClient(btn){
 api('PATCH','/api/clients',{ip:btn.dataset.ip,name:btn.closest('tr').querySelector('.c-name').value,profile:btn.closest('tr').querySelector('.c-profile').value,whitelisted:btn.dataset.white!=='true'}).then(loadClients);
}
function deleteClient(btn){
 api('DELETE','/api/clients',{ip:btn.dataset.ip}).then(function(){toast('Client removed','ok');loadClients();});
}
function clearDeniedClients(){
 api('POST','/api/clients/clear-denied',{}).then(function(r){toast('Cleared '+((r&&r.removed)||0)+' denied clients','ok');loadClients();});
}
function loadLg(){
 api('GET','/api/log').then(function(d){
  var tb=document.getElementById('logs');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="10" class="empty">No queries yet</td></tr>';return;}
  var f=(document.getElementById('log-filter')&&document.getElementById('log-filter').value||'').toLowerCase();
  var rows=d.reverse().filter(function(e){
   if(!f)return true;
   return [e.time,e.client,e.client_ip,e.client_name,e.transport,e.domain,e.answers,e.type,e.action,e.block_source].join(' ').toLowerCase().indexOf(f)>=0;
  });
  if(!rows.length){tb.innerHTML='<tr><td colspan="10" class="empty">No matching queries</td></tr>';return;}
  tb.innerHTML=rows.map(function(e){
   var c=e.client_name?e.client_name+' ('+e.client_ip+')':e.client_ip;
   var ans=e.answers||'-';
   return '<tr><td class="nowrap">'+esc(e.time)+'</td><td title="'+esc(e.client||'')+'">'+esc(c)+'</td><td><code>'+esc(e.transport||'-')+'</code></td><td><code>'+esc(e.domain)+'</code></td><td><code>'+esc(ans)+'</code></td><td>'+esc(e.type)+'</td><td><span class="tag tag-'+esc(e.action)+'">'+esc(e.action)+'</span></td><td><code>'+esc(e.block_source||'-')+'</code></td><td>'+e.duration_ms+'</td><td><div class="actions"><button class="sm dg" title="Block domain" data-domain="'+esc(e.domain)+'" onclick="blockFromLog(this)">D-</button><button class="sm ok" title="Allow domain" data-domain="'+esc(e.domain)+'" onclick="allowFromLog(this)">D+</button><button class="sm dg" title="Block returned IP" data-answer="'+esc(ans)+'" onclick="blockIPFromLog(this)">IP-</button><button class="sm ghost" title="Copy returned IP" data-answer="'+esc(ans)+'" onclick="copyAnswer(this)">CP</button></div></td></tr>';
  }).join('');
 });
}
function blockFromLog(btn){
 api('POST','/api/blocked',{domain:btn.dataset.domain}).then(function(r){if(r){toast('Blocked '+btn.dataset.domain,'ok')}loadLg();if(cur==='blocklist')loadBlk();});
}
function allowFromLog(btn){
 api('POST','/api/allowed',{domain:btn.dataset.domain}).then(function(r){if(r){toast('Allowed '+btn.dataset.domain,'ok')}loadLg();});
}
function blockIPFromLog(btn){
 var ip=(btn.dataset.answer||'').split(',')[0].trim();if(!ip||ip==='-'){toast('No IP answer to block','err');return;}
 api('POST','/api/blocked-ips',{ip:ip}).then(function(r){if(r){toast('Blocked IP '+ip,'ok')}loadLg();});
}
function copyAnswer(btn){
 if(navigator.clipboard)navigator.clipboard.writeText(btn.dataset.answer||'');
 toast('Copied answer','ok');
}
function loadSettings(){
 api('GET','/api/settings').then(function(d){
  if(!d)return;
  document.getElementById('set-listen').value=d.listen||'';
  document.getElementById('set-http').value=d.http||'';
  document.getElementById('set-https').value=d.https||'';
  document.getElementById('set-cert').value=d.tls_cert_file||'';
  document.getElementById('set-key').value=d.tls_key_file||'';
  document.getElementById('set-portal-host').value=d.portal_host||'dns.leaf';
  document.getElementById('set-portal-ip').value=d.portal_ip||'127.0.0.1';
  document.getElementById('set-blocklist').value=d.blocklist_file||'';
  document.getElementById('set-cache').checked=!!d.cache_enabled;
  document.getElementById('set-cache-size').value=d.cache_size||1000;
  document.getElementById('set-cache-ttl').value=d.cache_ttl_seconds||300;
  document.getElementById('set-resolver-disabled').checked=!!d.resolver_disabled;
  document.getElementById('set-lan').checked=!!d.lan_only;
  document.getElementById('set-whitelist-only').checked=!!d.whitelist_only;
  document.getElementById('set-whitelist').value=(d.whitelist||[]).join(', ');
  document.getElementById('set-direct-override').checked=!!d.direct_override;
  document.getElementById('set-direct-to').value=d.direct_override_to||d.portal_host||'dns.leaf';
  document.getElementById('set-troll').checked=!!d.troll_mode;
  document.getElementById('set-troll-hosts').value=(d.troll_hosts||[]).join('\n');
  document.getElementById('set-http-proxy-enabled').checked=!!d.http_proxy_enabled;
  document.getElementById('set-http-proxy').value=d.http_proxy||'';
  document.getElementById('set-socks-proxy-enabled').checked=!!d.socks_proxy_enabled;
  document.getElementById('set-socks-proxy').value=d.socks_proxy||'';
  renderProxyState(d);
 });
}
function renderProxyState(d){
 var hp=d.http_proxy||'',sp=d.socks_proxy||'',he=!!d.http_proxy_enabled&&!!hp,se=!!d.socks_proxy_enabled&&!!sp;
 document.getElementById('proxy-http-state').textContent=he?'On':'Off';
 document.getElementById('proxy-socks-state').textContent=se?'On':'Off';
 document.getElementById('proxy-http-url').textContent=he?hp:'disabled';
 document.getElementById('proxy-socks-url').textContent=se?sp:'disabled';
 var policy=d.whitelist_only?'whitelist':(d.lan_only?'LAN only':'open');
 document.getElementById('proxy-policy-state').textContent=policy;
 document.getElementById('proxy-allowed-state').textContent=policy;
}
function saveSettings(){
 api('PUT','/api/settings',{
  listen:document.getElementById('set-listen').value,
  http:document.getElementById('set-http').value,
  https:document.getElementById('set-https').value,
  tls_cert_file:document.getElementById('set-cert').value,
  tls_key_file:document.getElementById('set-key').value,
  portal_host:document.getElementById('set-portal-host').value,
  portal_ip:document.getElementById('set-portal-ip').value,
  blocklist_file:document.getElementById('set-blocklist').value,
  cache_enabled:document.getElementById('set-cache').checked,
  cache_size:parseInt(document.getElementById('set-cache-size').value,10)||1000,
  cache_ttl_seconds:parseInt(document.getElementById('set-cache-ttl').value,10)||300,
  resolver_disabled:document.getElementById('set-resolver-disabled').checked,
  lan_only:document.getElementById('set-lan').checked,
  whitelist_only:document.getElementById('set-whitelist-only').checked,
  whitelist:document.getElementById('set-whitelist').value.split(',').map(function(s){return s.trim();}).filter(Boolean),
  direct_override:document.getElementById('set-direct-override').checked,
  direct_override_to:document.getElementById('set-direct-to').value,
  troll_mode:document.getElementById('set-troll').checked,
  troll_hosts:splitLines(document.getElementById('set-troll-hosts').value),
  http_proxy_enabled:document.getElementById('set-http-proxy-enabled').checked,
  http_proxy:document.getElementById('set-http-proxy').value,
  socks_proxy_enabled:document.getElementById('set-socks-proxy-enabled').checked,
  socks_proxy:document.getElementById('set-socks-proxy').value
 }).then(function(d){toast(d?'Settings saved':'Settings saved (no response)','ok');loadSettings();});
}
function loadCertPage(){
 api('GET','/api/settings').then(function(d){
  var host=d.portal_host||'dns.leaf',ip=d.portal_ip||'127.0.0.1';
  if(!document.getElementById('cert-cn').value)document.getElementById('cert-cn').value=host;
  if(!document.getElementById('cert-dns').value)document.getElementById('cert-dns').value=host;
  if(!document.getElementById('cert-ips').value)document.getElementById('cert-ips').value=ip;
  if(!document.getElementById('cert-org').value)document.getElementById('cert-org').value='DNSLeaf local';
  if(!document.getElementById('cert-days').value)document.getElementById('cert-days').value='398';
  if(!document.getElementById('cert-cert-path').value)document.getElementById('cert-cert-path').value=d.tls_cert_file||'certs/dnsleaf-cert.pem';
  if(!document.getElementById('cert-key-path').value)document.getElementById('cert-key-path').value=d.tls_key_file||'certs/dnsleaf-key.pem';
  if(!document.getElementById('cert-https').value)document.getElementById('cert-https').value=d.https||':8443';
 });
}
function createCert(){
 var body={
  common_name:document.getElementById('cert-cn').value,
  dns_names:document.getElementById('cert-dns').value,
  ip_addresses:document.getElementById('cert-ips').value,
  organization:document.getElementById('cert-org').value,
  days:parseInt(document.getElementById('cert-days').value,10)||398,
  key_type:document.getElementById('cert-key-type').value,
  cert:document.getElementById('cert-cert-path').value,
  key:document.getElementById('cert-key-path').value,
  https:document.getElementById('cert-https').value,
  is_ca:document.getElementById('cert-is-ca').checked,
  apply:document.getElementById('cert-apply').checked
 };
 api('POST','/api/tls/selfsigned',body).then(function(r){
  document.getElementById('cert-result').innerHTML='Created <code>'+esc(r.cert)+'</code> and <code>'+esc(r.key)+'</code>. '+(r.applied?'Restart DNSLeaf to enable HTTPS on '+esc(r.https)+'.':'Files created; settings were not changed.');
 });
}
function loadServerLog(){
 api('GET','/api/server-log').then(function(d){
  var el=document.getElementById('serverlog');
  if(!d||!d.length){el.textContent='No server log entries yet.';return;}
  el.textContent=d.join('\n');
 });
}
function loadUsers(){
 api('GET','/api/users').then(function(d){
  var tb=document.getElementById('users');
  if(!d||!d.length){tb.innerHTML='<tr><td colspan="5" class="empty">No users configured</td></tr>';return;}
  tb.innerHTML=d.map(function(u){
   return '<tr><td><input class="u-name" value="'+esc(u.username)+'"></td><td><select class="u-role"><option value="viewer" '+(u.role==='viewer'?'selected':'')+'>Viewer</option><option value="admin" '+(u.role==='admin'?'selected':'')+'>Admin</option></select></td><td>'+esc(u.created_at||'')+'</td><td><input class="u-pass" type="password" placeholder="New password"></td><td><button class="sm ok" data-user="'+esc(u.username)+'" onclick="saveUser(this)">Save</button> <button class="sm dg" data-user="'+esc(u.username)+'" onclick="delUser(this)">Remove</button></td></tr>';
  }).join('');
 });
}
function addUser(){
 var u=document.getElementById('new-user').value,p=document.getElementById('new-pass').value,r=document.getElementById('new-role').value;
 if(!u||!p)return;
 api('POST','/api/users',{username:u,password:p,role:r}).then(function(){document.getElementById('new-user').value='';document.getElementById('new-pass').value='';loadUsers();});
}
function saveUser(btn){
 var tr=btn.closest('tr');
 api('PATCH','/api/users',{username:btn.dataset.user,new_username:tr.querySelector('.u-name').value,role:tr.querySelector('.u-role').value,password:tr.querySelector('.u-pass').value}).then(loadUsers);
}
function delUser(btn){api('DELETE','/api/users',{username:btn.dataset.user}).then(loadUsers);}
document.querySelectorAll('#tabs a[data-t]').forEach(function(a){a.addEventListener('click',function(){sw(this.dataset.t)})});
document.getElementById('btn-login').addEventListener('click',login);
document.getElementById('login-pass').addEventListener('keydown',function(e){if(e.key==='Enter')login();});
document.getElementById('logout').addEventListener('click',logout);
document.getElementById('btn-add-rec').addEventListener('click',addRec);
document.getElementById('btn-browse-zone').addEventListener('click',browseZone);
document.getElementById('import-file').addEventListener('change',pickedZone);
document.getElementById('btn-import-zone').addEventListener('click',importZone);
document.getElementById('btn-add-blk').addEventListener('click',addBlk);
document.getElementById('btn-add-rx').addEventListener('click',addRegex);
document.getElementById('b-dom').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addBlk();}});
document.getElementById('blk-filter').addEventListener('input',function(){blkPage=1;renderBlk();});
document.getElementById('blk-context').addEventListener('change',function(){blkPage=1;renderBlk();});
document.getElementById('blk-page-size').addEventListener('change',function(){blkPage=1;renderBlk();});
document.getElementById('blk-prev').addEventListener('click',function(){blkPage--;renderBlk();});
document.getElementById('blk-next').addEventListener('click',function(){blkPage++;renderBlk();});
document.getElementById('btn-reload-bl').addEventListener('click',function(){startGravity(document.getElementById('gravity-target').value)});
document.getElementById('gravity-close').addEventListener('click',function(){document.getElementById('gravity-modal').classList.remove('show');});
document.getElementById('btn-add-list').addEventListener('click',addList);
document.getElementById('bl-source').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addList();}});
document.getElementById('btn-save-group').addEventListener('click',saveGroup);
document.getElementById('grp-name').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();saveGroup();}});
document.getElementById('btn-add-up').addEventListener('click',addUp);
document.getElementById('u-addr').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addUp();}});
document.getElementById('btn-load-clients').addEventListener('click',loadClients);
document.getElementById('btn-clear-denied-clients').addEventListener('click',clearDeniedClients);
document.getElementById('btn-set-client-profile').addEventListener('click',assignClientProfile);
document.getElementById('cp-ip').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();assignClientProfile();}});
document.getElementById('btn-add-profile').addEventListener('click',addProfile);
document.getElementById('pf-name').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();addProfile();}});
document.getElementById('btn-clear-log').addEventListener('click',function(){api('DELETE','/api/log').then(loadLg);});
document.getElementById('log-filter').addEventListener('input',loadLg);
document.getElementById('btn-save-settings').addEventListener('click',saveSettings);
document.getElementById('btn-save-proxy').addEventListener('click',saveSettings);
document.getElementById('btn-create-cert').addEventListener('click',createCert);
document.getElementById('btn-refresh-serverlog').addEventListener('click',loadServerLog);
document.getElementById('btn-clear-serverlog').addEventListener('click',function(){api('DELETE','/api/server-log').then(loadServerLog);});
document.getElementById('btn-add-user').addEventListener('click',addUser);
document.addEventListener('keydown',function(e){
 if(e.key!=='Enter'||e.shiftKey||e.ctrlKey||e.altKey)return;
 var t=e.target;
 if(t.matches('.rec-host,.rec-ip,.rec-note')){e.preventDefault();saveRec(t.closest('tr').querySelector('button.ok'));}
 if(t.matches('.list-name,.list-groups')){e.preventDefault();saveList(t.closest('tr').querySelector('button.ok'));}
 if(t.matches('.c-name')){e.preventDefault();saveClient(t.closest('tr').querySelector('button.ok'));}
 if(t.matches('.u-name,.u-pass')){e.preventDefault();saveUser(t.closest('tr').querySelector('button.ok'));}
 if(t.matches('.grp-row-name')){e.preventDefault();saveGroupRow(t.closest('tr').querySelector('button.ok'));}
 if(t.matches('.pf-row-name')){e.preventDefault();saveProfileRow(t.closest('tr').querySelector('button.ok'));}
});
loadRememberedLogin();
checkSession();
setTimeout(function(){var t=(location.hash||'').replace('#','');if(t&&document.getElementById('t-'+t))sw(t);},0);
setInterval(function(){if(cur==='dashboard')loadSt();},3000);
</script>
</body></html>`

func defaultConfig() Config {
	return Config{
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
		BlockGroups:        []BlockGroup{},
		Cache:              true,
		CacheSize:          1000,
		CacheTTL:           300,
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
	maxCacheEntries = 1000000
	maxCacheTTL     = 7 * 24 * 60 * 60
)

func validateConfig(cfg Config) error {
	var issues []string
	add := func(field, message string) { issues = append(issues, field+" "+message) }
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
	if len(cfg.Upstreams) == 0 && !cfg.ResolverDisabled {
		add("upstreams", "at least one upstream is required unless resolver_disabled is enabled")
	}
	for i, upstream := range cfg.Upstreams {
		if err := validateNetworkAddress(upstream, false); err != nil {
			add(fmt.Sprintf("upstreams[%d]", i), err.Error())
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
		gravityByList:      make(map[string][]uint32),
		cache:              make(map[string]cacheEntry),
		log:                make([]QueryEntry, 0, 200),
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

func (d *DNSLeaf) loadPersistentState() {
	data, err := os.ReadFile(d.statePath)
	if err != nil {
		return
	}
	var state PersistentState
	if json.Unmarshal(data, &state) != nil {
		return
	}
	d.stats = state.Stats
	if len(state.Log) > 200 {
		state.Log = state.Log[len(state.Log)-200:]
	}
	d.log = state.Log
	if state.Clients != nil {
		d.clientsMu.Lock()
		for ip, item := range state.Clients {
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

func (d *DNSLeaf) savePersistentState() {
	d.statsMu.Lock()
	stats := d.stats
	d.statsMu.Unlock()
	d.logMu.Lock()
	logCopy := make([]QueryEntry, len(d.log))
	copy(logCopy, d.log)
	d.logMu.Unlock()
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
	data, err := json.MarshalIndent(PersistentState{Stats: stats, Log: logCopy, Clients: clientsCopy}, "", "  ")
	if err != nil {
		return
	}
	_ = atomicWriteFile(d.statePath, data, 0600)
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
				d.savePersistentState()
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
			d.savePersistentState()
		case <-d.stateStopCh:
			d.savePersistentState()
			return
		}
	}
}

func (d *DNSLeaf) stopPersistentState() {
	d.stateStopOnce.Do(func() { close(d.stateStopCh) })
	<-d.stateDoneCh
}

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

func (d *DNSLeaf) ensureAuth() {
	if !d.cfg.Auth.Enabled {
		return
	}
	if len(d.cfg.Auth.Users) > 0 {
		return
	}
	password := randomToken(12)
	d.cfg.Auth.Users = []UserAuth{{
		Username:     "admin",
		PasswordHash: passwordHash(password),
		Role:         "admin",
		CreatedAt:    time.Now().Format(time.RFC3339),
	}}
	if err := d.saveConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "[DNSLeaf] could not save generated admin user: %v\n", err)
	}
	fmt.Println("[DNSLeaf] generated web admin credentials")
	fmt.Println("[DNSLeaf] username: admin")
	fmt.Printf("[DNSLeaf] password: %s\n", password)
	fmt.Println("[DNSLeaf] save this password now; reset by removing auth.users from config.json")
}

func (d *DNSLeaf) findUser(username string) (UserAuth, bool) {
	for _, user := range d.cfg.Auth.Users {
		if user.Username == username {
			return user, true
		}
	}
	return UserAuth{}, false
}

func validUsername(username string) bool {
	if username == "" || len(username) > 64 {
		return false
	}
	for _, r := range username {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func adminCount(users []UserAuth) int {
	count := 0
	for _, user := range users {
		if user.Role == "admin" {
			count++
		}
	}
	return count
}

func (d *DNSLeaf) revokeUserSessions(username string) {
	d.sessMu.Lock()
	for token, session := range d.sessions {
		if session.Username == username {
			delete(d.sessions, token)
		}
	}
	d.sessMu.Unlock()
}

func (d *DNSLeaf) sessionFromRequest(r *http.Request) (Session, bool) {
	if !d.cfg.Auth.Enabled {
		return Session{Username: "local", Role: "admin", Expires: time.Now().Add(time.Hour)}, true
	}
	cookie, err := r.Cookie("dnsleaf_session")
	if err != nil || cookie.Value == "" {
		return Session{}, false
	}
	d.sessMu.Lock()
	defer d.sessMu.Unlock()
	s, ok := d.sessions[cookie.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(d.sessions, cookie.Value)
		return Session{}, false
	}
	return s, true
}

func (d *DNSLeaf) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/dnsleaf.png" || r.URL.Path == "/dns-query" || r.URL.Path == "/api/ping" || r.URL.Path == "/api/login" || r.URL.Path == "/api/session" {
			next.ServeHTTP(w, r)
			return
		}
		s, ok := d.sessionFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/api/users" && s.Role != "admin" {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		if r.Method != "GET" && s.Role != "admin" {
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type bufferedResponseWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponseWriter() *bufferedResponseWriter {
	return &bufferedResponseWriter{header: make(http.Header)}
}

func (w *bufferedResponseWriter) Header() http.Header { return w.header }

func (w *bufferedResponseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *bufferedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(data)
}

func (w *bufferedResponseWriter) flush(dst http.ResponseWriter) {
	for key, values := range w.header {
		for _, value := range values {
			dst.Header().Add(key, value)
		}
	}
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	dst.WriteHeader(status)
	if w.body.Len() > 0 && status != http.StatusNoContent {
		_, _ = dst.Write(w.body.Bytes())
	}
}

func cloneConfig(cfg Config) (Config, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return Config{}, err
	}
	var clone Config
	if err := json.Unmarshal(data, &clone); err != nil {
		return Config{}, err
	}
	return clone, nil
}

func (d *DNSLeaf) configGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dns-query" {
			next.ServeHTTP(w, r)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, 64*1024*1024)
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			d.cfgMu.RLock()
			defer d.cfgMu.RUnlock()
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-DNSLeaf-Request") != "1" {
			http.Error(w, "missing X-DNSLeaf-Request header", http.StatusForbidden)
			return
		}
		d.cfgMu.Lock()
		defer d.cfgMu.Unlock()
		before, err := cloneConfig(d.cfg)
		if err != nil {
			http.Error(w, "could not snapshot configuration", http.StatusInternalServerError)
			return
		}
		buffered := newBufferedResponseWriter()
		next.ServeHTTP(buffered, r)
		status := buffered.status
		if status == 0 {
			status = http.StatusOK
		}
		if status >= 200 && status < 300 {
			if err := validateConfig(d.cfg); err != nil {
				d.cfg = before
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := d.saveConfigLocked(); err != nil {
				d.cfg = before
				http.Error(w, "could not save configuration", http.StatusInternalServerError)
				return
			}
			d.clearCache()
		}
		buffered.flush(w)
	})
}

func isRemoteBlocklistSource(source string) bool {
	return strings.HasPrefix(strings.TrimSpace(source), "http://") || strings.HasPrefix(strings.TrimSpace(source), "https://")
}

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
		if data, err := os.ReadFile(cachePath); err == nil {
			return data, true, nil
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
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

func domainRuleMatches(rule, name string) bool {
	rule = normalizeDomainRule(rule)
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if rule == "" || name == "" {
		return false
	}
	if isRegexRule(rule) {
		re := regexRulePattern(rule)
		if re == "" {
			return false
		}
		ok, err := regexp.MatchString(re, name)
		return err == nil && ok
	}
	if strings.Contains(rule, "*") {
		ok, err := regexp.MatchString(wildcardRulePattern(rule), name)
		return err == nil && ok
	}
	return rule == name
}

func validateDomainRule(rule string) error {
	rule = normalizeDomainRule(rule)
	if rule == "" {
		return fmt.Errorf("domain required")
	}
	if isRegexRule(rule) {
		if _, err := regexp.Compile(regexRulePattern(rule)); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
		return nil
	}
	if strings.Contains(rule, "*") {
		if _, err := regexp.Compile(wildcardRulePattern(rule)); err != nil {
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
	if fromCache && src.LastError == "" {
		src.LastError = "loaded from gravity cache"
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
			if domainRuleMatches(allowed, domain) {
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
			if domainRuleMatches(allow, name) {
				return false, ""
			}
		}
		for _, blocked := range profile.Blocked {
			if domainRuleMatches(blocked, name) {
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
		if domainRuleMatches(allow, name) {
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
		if domainRuleMatches(rule, name) {
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
		if !rule.Enabled || !domainRuleMatches(rule.Domain, name) || !scheduledRuleActive(rule, now) {
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

func (d *DNSLeaf) resolveLocal(qname string, qtype uint16) []dns.RR {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	var results []dns.RR
	portalHost := strings.ToLower(strings.TrimSuffix(d.cfg.PortalHost, "."))
	if portalHost != "" && name == portalHost {
		ip := net.ParseIP(d.cfg.PortalIP)
		if qtype == dns.TypeA && ip != nil && ip.To4() != nil {
			return []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: ip}}
		}
		if qtype == dns.TypeAAAA && ip != nil && ip.To4() == nil {
			return []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: ip}}
		}
		if qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB {
			port := uint16(443)
			if d.cfg.HTTPS == "" && strings.Contains(d.cfg.HTTP, ":") {
				if _, p, err := net.SplitHostPort(d.cfg.HTTP); err == nil && p != "" {
					fmt.Sscanf(p, "%d", &port)
				}
			}
			return []dns.RR{&dns.SVCB{
				Hdr:      dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 300},
				Priority: 1,
				Target:   ".",
				Value:    []dns.SVCBKeyValue{&dns.SVCBPort{Port: port}},
			}}
		}
	}
	for _, rec := range d.cfg.Records {
		if strings.ToLower(rec.Host) != name {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if recType == "" {
			if strings.Contains(rec.IP, ":") {
				recType = "AAAA"
			} else {
				recType = "A"
			}
		}
		value := strings.TrimSpace(rec.Value)
		if value == "" {
			value = strings.TrimSpace(rec.IP)
		}
		if qtype == dns.TypeHTTPS || qtype == dns.TypeSVCB {
			matched := recType == "A" || recType == "AAAA" || recType == "HTTPS" || recType == "SVCB"
			if matched {
				results = append(results, &dns.SVCB{
					Hdr:      dns.RR_Header{Name: qname, Rrtype: qtype, Class: dns.ClassINET, Ttl: 300},
					Priority: 1,
					Target:   ".",
				})
			}
			continue
		}
		ip := net.ParseIP(value)
		if qtype == dns.TypeA && recType == "A" && ip != nil && ip.To4() != nil {
			results = append(results, &dns.A{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   ip,
			})
		} else if qtype == dns.TypeAAAA && recType == "AAAA" && ip != nil {
			results = append(results, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
				AAAA: ip,
			})
		} else if qtype == dns.TypeTXT && recType == "TXT" && value != "" {
			results = append(results, &dns.TXT{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
				Txt: []string{value},
			})
		} else if qtype == dns.TypeCNAME && recType == "CNAME" && value != "" {
			results = append(results, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
				Target: dns.Fqdn(value),
			})
		} else if qtype == dns.TypeMX && recType == "MX" && value != "" {
			results = append(results, &dns.MX{
				Hdr:        dns.RR_Header{Name: qname, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
				Preference: rec.Priority,
				Mx:         dns.Fqdn(value),
			})
		} else if qtype == dns.TypeSRV && recType == "SRV" && value != "" {
			results = append(results, &dns.SRV{
				Hdr:      dns.RR_Header{Name: qname, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 3600},
				Priority: rec.Priority,
				Weight:   rec.Weight,
				Port:     rec.Port,
				Target:   dns.Fqdn(value),
			})
		} else if qtype == dns.TypePTR && recType == "PTR" && value != "" {
			results = append(results, &dns.PTR{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
				Ptr: dns.Fqdn(value),
			})
		}
	}
	return results
}

func (d *DNSLeaf) resolvePortal(qname string, qtype uint16) []dns.RR {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	portalHost := strings.ToLower(strings.TrimSuffix(d.cfg.PortalHost, "."))
	if portalHost == "" || name != portalHost {
		return nil
	}
	return d.resolveLocal(qname, qtype)
}

func normalizeClientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

func ipInList(ip string, list []string) bool {
	parsed := net.ParseIP(ip)
	for _, raw := range list {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil && parsed != nil {
			if network.Contains(parsed) {
				return true
			}
			continue
		}
		if itemIP := net.ParseIP(item); itemIP != nil && parsed != nil {
			if itemIP.Equal(parsed) {
				return true
			}
			continue
		}
		if item == ip {
			return true
		}
	}
	return false
}

func normalizeIPOrCIDR(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("ip required")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if ip, network, err := net.ParseCIDR(value); err == nil {
		network.IP = ip.Mask(network.Mask)
		return network.String(), nil
	}
	return "", fmt.Errorf("invalid IP or CIDR: %s", value)
}

func isLANIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

func (d *DNSLeaf) clientAllowed(ip string) bool {
	if d.cfg.WhitelistOnly {
		return ipInList(ip, d.cfg.Whitelist)
	}
	if d.cfg.LANOnly && !isLANIP(ip) && !ipInList(ip, d.cfg.Whitelist) {
		return false
	}
	return true
}

func (d *DNSLeaf) clientName(ip string) string {
	if d.cfg.ClientNames == nil {
		return ""
	}
	if name := d.cfg.ClientNames[ip]; name != "" {
		return name
	}
	return d.dhcpClientName(ip)
}

func (d *DNSLeaf) dhcpClientName(ip string) string {
	if d.cfg.DHCPLeasesFile == "" {
		return ""
	}
	data, err := os.ReadFile(d.runtimePath(d.cfg.DHCPLeasesFile))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[2] == ip && fields[3] != "*" {
			return fields[3]
		}
		if len(fields) >= 2 && fields[0] == ip {
			return fields[1]
		}
	}
	return ""
}

func (d *DNSLeaf) trackClient(ip, action string) {
	d.clientsMu.Lock()
	defer d.clientsMu.Unlock()
	c := d.clients[ip]
	if c == nil {
		c = &clientState{}
		d.clients[ip] = c
	}
	c.queries++
	c.lastSeen = time.Now()
	switch action {
	case "blocked":
		c.blocked++
	case "local":
		c.local++
	case "cached":
		c.cached++
	case "forwarded":
		c.forwarded++
	case "denied":
		c.denied++
	case "trolled":
		c.trolled++
	}
	d.requestPersistentSave()
}

func (d *DNSLeaf) disabledUpstream(addr string) bool {
	d.healthMu.RLock()
	if d.unhealthyUpstreams[addr] {
		d.healthMu.RUnlock()
		return true
	}
	d.healthMu.RUnlock()
	for _, item := range d.cfg.DisabledUpstreams {
		if item == addr {
			return true
		}
	}
	return false
}

func (d *DNSLeaf) rateLimited(ip string) bool {
	if !d.cfg.RateLimit.Enabled || d.cfg.RateLimit.Queries <= 0 || d.cfg.RateLimit.Window <= 0 || ip == "" {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-time.Duration(d.cfg.RateLimit.Window) * time.Second)
	d.rateMu.Lock()
	defer d.rateMu.Unlock()
	hits := d.rateHits[ip]
	n := 0
	for _, hit := range hits {
		if hit.After(cutoff) {
			hits[n] = hit
			n++
		}
	}
	hits = hits[:n]
	hits = append(hits, now)
	d.rateHits[ip] = hits
	return len(hits) > d.cfg.RateLimit.Queries
}

func (d *DNSLeaf) noteAnomaly(qname, source string) {
	if !d.cfg.Anomaly.Enabled || d.cfg.Anomaly.Hits <= 0 || d.cfg.Anomaly.Window <= 0 {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	now := time.Now()
	cutoff := now.Add(-time.Duration(d.cfg.Anomaly.Window) * time.Second)
	d.anomalyMu.Lock()
	hits := d.anomalyHits[name]
	n := 0
	for _, hit := range hits {
		if hit.After(cutoff) {
			hits[n] = hit
			n++
		}
	}
	hits = append(hits[:n], now)
	d.anomalyHits[name] = hits
	count := len(hits)
	d.anomalyMu.Unlock()
	if count == d.cfg.Anomaly.Hits {
		d.addServerLog(fmt.Sprintf("warning: blocked domain %s hit %d times in %ds source=%s", name, count, d.cfg.Anomaly.Window, source))
	}
}

func (d *DNSLeaf) getCached(key string) *dns.Msg {
	if !d.cfg.Cache {
		return nil
	}
	now := time.Now()
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	e, ok := d.cache[key]
	if !ok || !now.Before(e.expiresAt) {
		if ok {
			delete(d.cache, key)
		}
		return nil
	}
	msg := e.msg.Copy()
	elapsed := uint32(now.Sub(e.storedAt) / time.Second)
	decrementMessageTTL(msg, elapsed)
	return msg
}

func (d *DNSLeaf) clearCache() {
	d.cacheMu.Lock()
	d.cache = make(map[string]cacheEntry)
	d.cacheMu.Unlock()
}

func (d *DNSLeaf) setCache(key string, msg *dns.Msg) {
	if !d.cfg.Cache {
		return
	}
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if d.cfg.CacheSize <= 0 {
		return
	}
	if len(d.cache) >= d.cfg.CacheSize {
		for k := range d.cache {
			delete(d.cache, k)
			break
		}
	}
	ttl := messageCacheTTL(msg, time.Duration(d.cfg.CacheTTL)*time.Second)
	if ttl <= 0 {
		return
	}
	now := time.Now()
	d.cache[key] = cacheEntry{msg: msg.Copy(), storedAt: now, expiresAt: now.Add(ttl)}
}

func messageCacheTTL(msg *dns.Msg, configured time.Duration) time.Duration {
	if msg == nil || configured <= 0 || msg.Truncated {
		return 0
	}
	minTTL := uint32(^uint32(0))
	found := false
	var negativeSOA *dns.SOA
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr == nil {
				continue
			}
			if _, ok := rr.(*dns.OPT); ok {
				continue
			}
			ttl := rr.Header().Ttl
			if ttl == 0 {
				return 0
			}
			if ttl < minTTL {
				minTTL = ttl
			}
			if soa, ok := rr.(*dns.SOA); ok {
				negativeSOA = soa
			}
			found = true
		}
	}
	if !found {
		return 0
	}
	negative := msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0)
	if negative {
		if negativeSOA == nil {
			return 0
		}
		if negativeSOA.Minttl < minTTL {
			minTTL = negativeSOA.Minttl
		}
		if minTTL == 0 {
			return 0
		}
	}
	ttl := time.Duration(minTTL) * time.Second
	if ttl > configured {
		return configured
	}
	return ttl
}

func decrementMessageTTL(msg *dns.Msg, elapsed uint32) {
	if elapsed == 0 || msg == nil {
		return
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			header := rr.Header()
			if header.Ttl > elapsed {
				header.Ttl -= elapsed
			} else {
				header.Ttl = 0
			}
		}
	}
}

func (d *DNSLeaf) forward(r *dns.Msg) *dns.Msg {
	udpClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	tcpClient := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	configured := d.upstreamsForQuery(r)
	addrs := make([]string, 0, len(configured))
	for _, addr := range configured {
		if !d.disabledUpstream(addr) {
			addrs = append(addrs, addr)
		}
	}
	mathrand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	for _, addr := range addrs {
		resp, _, err := udpClient.Exchange(r, addr)
		if err != nil {
			continue
		}
		if resp.Truncated {
			resp, _, err = tcpClient.Exchange(r, addr)
			if err != nil {
				continue
			}
		}
		return resp
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	return m
}

func (d *DNSLeaf) upstreamsForQuery(r *dns.Msg) []string {
	if len(r.Question) == 0 {
		return d.cfg.Upstreams
	}
	name := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
	for _, rule := range d.cfg.ConditionalForward {
		if !rule.Enabled || len(rule.Upstreams) == 0 {
			continue
		}
		suffix := strings.ToLower(strings.Trim(strings.TrimSpace(rule.Suffix), "."))
		if suffix != "" && (name == suffix || strings.HasSuffix(name, "."+suffix)) {
			return rule.Upstreams
		}
	}
	return d.cfg.Upstreams
}

func (d *DNSLeaf) monitorUpstreams() {
	d.cfgMu.RLock()
	health := d.cfg.UpstreamHealth
	d.cfgMu.RUnlock()
	if !health.Enabled {
		return
	}
	interval := time.Duration(health.Interval) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	failuresNeeded := health.Failures
	if failuresNeeded <= 0 {
		failuresNeeded = 3
	}
	failures := map[string]int{}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		d.cfgMu.RLock()
		upstreams := append([]string(nil), d.cfg.Upstreams...)
		health = d.cfg.UpstreamHealth
		d.cfgMu.RUnlock()
		timeout := time.Duration(health.Timeout) * time.Millisecond
		if timeout <= 0 {
			timeout = 1200 * time.Millisecond
		}
		for _, upstream := range upstreams {
			ok := d.probeUpstream(upstream, timeout)
			d.healthMu.Lock()
			wasBad := d.unhealthyUpstreams[upstream]
			if ok {
				failures[upstream] = 0
				delete(d.unhealthyUpstreams, upstream)
				if wasBad {
					d.addServerLog("upstream healthy again: " + upstream)
				}
			} else {
				failures[upstream]++
				if failures[upstream] >= failuresNeeded {
					d.unhealthyUpstreams[upstream] = true
					if !wasBad {
						d.addServerLog("upstream auto-disabled: " + upstream)
					}
				}
			}
			d.healthMu.Unlock()
		}
		select {
		case <-ticker.C:
		case <-d.stopCh:
			return
		}
	}
}

func (d *DNSLeaf) probeUpstream(addr string, timeout time.Duration) bool {
	m := new(dns.Msg)
	m.SetQuestion("dns.leaf.", dns.TypeA)
	c := &dns.Client{Net: "udp", Timeout: timeout}
	_, _, err := c.Exchange(m, addr)
	return err == nil
}

func dnsAnswers(msg *dns.Msg) string {
	if msg == nil || len(msg.Answer) == 0 {
		return ""
	}
	answers := make([]string, 0, len(msg.Answer))
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			answers = append(answers, v.A.String())
		case *dns.AAAA:
			answers = append(answers, v.AAAA.String())
		case *dns.CNAME:
			answers = append(answers, strings.TrimSuffix(v.Target, "."))
		}
	}
	return strings.Join(answers, ", ")
}

func lookupClientMAC(ip string) (string, string) {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return "", "skipped: loopback/local source"
	}
	out, err := exec.Command("arp", "-a", ip).Output()
	if err != nil {
		out, err = exec.Command("arp", "-a").Output()
	}
	if err != nil {
		return "", "arp lookup failed: " + err.Error()
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, ip) {
			continue
		}
		for _, field := range strings.Fields(line) {
			mac := normalizeMAC(field)
			if mac != "" {
				return mac, "resolved from ARP"
			}
		}
		return "", "ARP entry found without MAC"
	}
	return "", "not in ARP cache"
}

func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for _, part := range parts {
		if len(part) != 2 {
			return ""
		}
		if _, err := strconv.ParseUint(part, 16, 8); err != nil {
			return ""
		}
	}
	return strings.Join(parts, ":")
}

func (d *DNSLeaf) answerBlocked(msg *dns.Msg) bool {
	if msg == nil || len(d.cfg.BlockedIPs) == 0 {
		return false
	}
	for _, rr := range msg.Answer {
		var ip string
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A.String()
		case *dns.AAAA:
			ip = v.AAAA.String()
		}
		if ip == "" {
			continue
		}
		for _, blocked := range d.cfg.BlockedIPs {
			if ip == blocked || ipInList(ip, []string{blocked}) {
				return true
			}
		}
	}
	return false
}

func blockedResponse(r *dns.Msg, qname string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	if qtype == dns.TypeA {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
			A:   net.ParseIP("0.0.0.0"),
		})
	} else if qtype == dns.TypeAAAA {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
			AAAA: net.ParseIP("::"),
		})
	}
	return m
}

func (d *DNSLeaf) safeSearchResponse(r *dns.Msg, qname string, qtype uint16, clientIP string) *dns.Msg {
	_, profile, ok := d.profileForClient(clientIP)
	if !ok || !profile.SafeSearch || profile.DisableBlocking || profile.Disabled || qtype != dns.TypeA {
		return nil
	}
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	target := ""
	if safeSearchGoogle(name) {
		target = "216.239.38.120"
	} else if safeSearchBing(name) {
		target = "204.79.197.220"
	} else if safeSearchYouTube(name) {
		target = "216.239.38.120"
	}
	if target == "" {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = append(m.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(target),
	})
	return m
}

func safeSearchGoogle(name string) bool {
	return name == "google.com" || strings.HasPrefix(name, "www.google.") || strings.HasPrefix(name, "google.") || strings.Contains(name, ".google.")
}

func safeSearchBing(name string) bool {
	return name == "bing.com" || strings.HasSuffix(name, ".bing.com")
}

func safeSearchYouTube(name string) bool {
	return name == "youtube.com" || strings.HasSuffix(name, ".youtube.com") || name == "youtube.googleapis.com" || name == "youtubei.googleapis.com" || strings.HasSuffix(name, ".youtube-nocookie.com")
}

func (d *DNSLeaf) deniedClientResponse(r *dns.Msg, qname string, qtype uint16) (*dns.Msg, string) {
	if d.cfg.DirectOverride {
		return d.directOverrideResponse(r, qname, qtype), "override"
	}
	if d.cfg.TrollMode {
		return d.trollResponse(r, qname, qtype), "trolled"
	}
	return nil, ""
}

func (d *DNSLeaf) directOverrideResponse(r *dns.Msg, qname string, qtype uint16) *dns.Msg {
	target := strings.TrimSpace(d.cfg.DirectOverrideTo)
	if target == "" {
		target = d.cfg.PortalHost
	}
	if target == "" {
		return nil
	}
	if ip := net.ParseIP(target); ip != nil {
		return responseWithIP(r, qname, qtype, ip)
	}
	if rr := d.resolveLocal(dns.Fqdn(target), qtype); len(rr) > 0 {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, item := range rr {
			cp := dns.Copy(item)
			cp.Header().Name = qname
			m.Answer = append(m.Answer, cp)
		}
		return m
	}
	if ip := net.ParseIP(d.cfg.PortalIP); ip != nil {
		return responseWithIP(r, qname, qtype, ip)
	}
	return nil
}

func (d *DNSLeaf) trollResponse(r *dns.Msg, qname string, qtype uint16) *dns.Msg {
	if qtype != dns.TypeA && qtype != dns.TypeAAAA {
		return emptyNoErrorResponse(r)
	}
	if ip := d.randomTrollIP(qtype); ip != nil {
		return responseWithIP(r, qname, qtype, ip)
	}
	return emptyNoErrorResponse(r)
}

func (d *DNSLeaf) randomTrollIP(qtype uint16) net.IP {
	hosts := cleanStringList(d.cfg.TrollHosts)
	if len(hosts) == 0 {
		hosts = []string{"4chan.org", "neopets.com", "homestarrunner.com", "theonion.com", "archive.org", "wikipedia.org"}
	}
	mathrand.Shuffle(len(hosts), func(i, j int) { hosts[i], hosts[j] = hosts[j], hosts[i] })
	for _, host := range hosts {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		resp := d.forward(m)
		ips := ipsFromDNS(resp, qtype)
		if len(ips) > 0 {
			return ips[mathrand.Intn(len(ips))]
		}
	}
	var pool []string
	if qtype == dns.TypeAAAA {
		pool = d.cfg.TrollIPv6
	} else {
		pool = d.cfg.TrollIPv4
	}
	ips := make([]net.IP, 0, len(pool))
	for _, item := range pool {
		ip := net.ParseIP(strings.TrimSpace(item))
		if ip == nil {
			continue
		}
		if qtype == dns.TypeAAAA && ip.To4() == nil {
			ips = append(ips, ip)
		} else if qtype == dns.TypeA && ip.To4() != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) > 0 {
		return ips[mathrand.Intn(len(ips))]
	}
	return nil
}

func ipsFromDNS(msg *dns.Msg, qtype uint16) []net.IP {
	if msg == nil {
		return nil
	}
	ips := []net.IP{}
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				ips = append(ips, v.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				ips = append(ips, v.AAAA)
			}
		}
	}
	return ips
}

func responseWithIP(r *dns.Msg, qname string, qtype uint16, ip net.IP) *dns.Msg {
	if ip == nil {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(r)
	if qtype == dns.TypeA && ip.To4() != nil {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip})
		return m
	}
	if qtype == dns.TypeAAAA && ip.To4() == nil {
		m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: ip})
		return m
	}
	return emptyNoErrorResponse(r)
}

func emptyNoErrorResponse(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	return m
}

func (d *DNSLeaf) addLog(client, localAddr, transport, domain, qtype, action, answers string, dur time.Duration, blockSource ...string) {
	ip := normalizeClientIP(client)
	name := d.clientName(ip)
	mac, macStatus := lookupClientMAC(ip)
	d.noteSource(ip, client, localAddr, transport, mac, macStatus)
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
		Client:      client,
		ClientIP:    ip,
		ClientName:  name,
		ClientMAC:   mac,
		MACStatus:   macStatus,
		LocalAddr:   localAddr,
		Transport:   transport,
		Domain:      domain,
		Answers:     answers,
		Type:        qtype,
		Action:      action,
		BlockSource: source,
		Duration:    dur.Milliseconds(),
	})
	if len(d.log) > 200 {
		d.log = d.log[len(d.log)-200:]
	}
	d.requestPersistentSave()
}

func (d *DNSLeaf) noteSource(ip, remote, localAddr, transport, mac, macStatus string) {
	key := transport + "|" + ip + "|" + localAddr
	d.seenMu.Lock()
	if d.seenSource[key] {
		d.seenMu.Unlock()
		return
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

func (d *DNSLeaf) HandleDNS(w dns.ResponseWriter, r *dns.Msg) {
	transport := "dns"
	client := ""
	if w.RemoteAddr() != nil {
		transport = w.RemoteAddr().Network()
		client = w.RemoteAddr().String()
	}
	localAddr := ""
	if w.LocalAddr() != nil {
		localAddr = w.LocalAddr().String()
	}
	resp := d.resolveDNS(r, client, localAddr, transport)
	if resp == nil {
		resp = new(dns.Msg)
		base := r
		if base == nil {
			base = new(dns.Msg)
		}
		resp.SetRcode(base, dns.RcodeServerFailure)
	}
	w.WriteMsg(resp)
}

func (d *DNSLeaf) resolveDNS(r *dns.Msg, client, localAddr, transport string) *dns.Msg {
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	if r == nil || len(r.Question) != 1 {
		m := new(dns.Msg)
		base := r
		if base == nil {
			base = new(dns.Msg)
		}
		m.SetRcode(base, dns.RcodeFormatError)
		return m
	}

	q := r.Question[0]
	qname := q.Name
	qtypeStr := dns.TypeToString[q.Qtype]
	clientIP := normalizeClientIP(client)
	start := time.Now()

	if portalRR := d.resolvePortal(qname, q.Qtype); len(portalRR) > 0 {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = portalRR
		dur := time.Since(start)
		d.addStat("local")
		d.trackClient(clientIP, "local")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "local", dnsAnswers(m), dur, "portal")
		return m
	}

	if d.cfg.ResolverDisabled {
		resp := d.forward(r)
		resp.Compress = true
		dur := time.Since(start)
		d.addStat("forwarded")
		d.trackClient(clientIP, "forwarded")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "forwarded", dnsAnswers(resp), dur)
		return resp
	}

	if d.rateLimited(clientIP) {
		m := new(dns.Msg)
		if strings.EqualFold(d.cfg.RateLimit.Action, "drop") {
			m.SetRcode(r, dns.RcodeServerFailure)
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
		dur := time.Since(start)
		d.addStat("denied")
		d.trackClient(clientIP, "denied")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "denied", "", dur, "rate-limit")
		return m
	}

	if !d.clientAllowed(clientIP) {
		if denied, mode := d.deniedClientResponse(r, qname, q.Qtype); denied != nil {
			dur := time.Since(start)
			d.addStat("denied")
			if mode == "trolled" {
				d.trackClient(clientIP, "trolled")
			} else {
				d.trackClient(clientIP, "denied")
			}
			d.addLog(client, localAddr, transport, qname, qtypeStr, mode, dnsAnswers(denied), dur, "access-policy")
			return denied
		}
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		dur := time.Since(start)
		d.addStat("denied")
		d.trackClient(clientIP, "denied")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "denied", "", dur)
		return m
	}

	if safe := d.safeSearchResponse(r, qname, q.Qtype, clientIP); safe != nil {
		dur := time.Since(start)
		d.addStat("local")
		d.trackClient(clientIP, "local")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "local", dnsAnswers(safe), dur, "safe-search")
		return safe
	}

	if blocked, source := d.blockDecision(qname, clientIP); blocked {
		m := blockedResponse(r, qname, q.Qtype)
		dur := time.Since(start)
		d.addStat("blocked")
		d.trackClient(clientIP, "blocked")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "blocked", dnsAnswers(m), dur, source)
		d.noteAnomaly(qname, source)
		return m
	}

	if localRR := d.resolveLocal(qname, q.Qtype); len(localRR) > 0 {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = localRR
		dur := time.Since(start)
		d.addStat("local")
		d.trackClient(clientIP, "local")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "local", dnsAnswers(m), dur)
		return m
	}

	cacheKey, cacheable := cacheKeyForMessage(r)
	if cacheable {
		if cached := d.getCached(cacheKey); cached != nil {
			if d.answerBlocked(cached) {
				m := blockedResponse(r, qname, q.Qtype)
				dur := time.Since(start)
				d.addStat("blocked")
				d.trackClient(clientIP, "blocked")
				d.addLog(client, localAddr, transport, qname, qtypeStr, "blocked", dnsAnswers(cached), dur, "blocked-ip")
				d.noteAnomaly(qname, "blocked-ip")
				return m
			}
			cached.Id = r.Id
			if len(cached.Question) > 0 {
				cached.Question[0] = q
			}
			dur := time.Since(start)
			d.addStat("cached")
			d.trackClient(clientIP, "cached")
			d.addLog(client, localAddr, transport, qname, qtypeStr, "cached", dnsAnswers(cached), dur)
			return cached
		}
	}

	resp := d.forward(r)
	if d.answerBlocked(resp) {
		blocked := blockedResponse(r, qname, q.Qtype)
		blocked.Compress = true
		dur := time.Since(start)
		d.addStat("blocked")
		d.trackClient(clientIP, "blocked")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "blocked", dnsAnswers(resp), dur, "blocked-ip")
		d.noteAnomaly(qname, "blocked-ip")
		return blocked
	}
	resp.Compress = true
	dur := time.Since(start)
	action := "forwarded"
	if resp.Rcode == dns.RcodeServerFailure {
		action = "error"
	}
	d.addStat(action)
	d.trackClient(clientIP, action)
	d.addLog(client, localAddr, transport, qname, qtypeStr, action, dnsAnswers(resp), dur)
	if cacheable && d.cfg.Cache && resp.Rcode != dns.RcodeServerFailure {
		d.setCache(cacheKey, resp)
	}
	return resp
}

func cacheKeyForMessage(r *dns.Msg) (string, bool) {
	if r == nil || len(r.Question) != 1 {
		return "", false
	}
	opt := r.IsEdns0()
	ednsSize := uint16(0)
	ednsVersion := uint8(0)
	ednsDO := false
	if opt != nil {
		if len(opt.Option) > 0 {
			return "", false
		}
		ednsSize = opt.UDPSize()
		ednsVersion = opt.Version()
		ednsDO = opt.Do()
	}
	q := r.Question[0]
	return fmt.Sprintf("%s:%d:%d:%t:%t:%t:%d:%d:%t", strings.ToLower(q.Name), q.Qtype, q.Qclass, r.RecursionDesired, r.CheckingDisabled, r.AuthenticatedData, ednsSize, ednsVersion, ednsDO), true
}

func (d *DNSLeaf) handleDoH(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	switch r.Method {
	case "GET":
		param := r.URL.Query().Get("dns")
		if param == "" {
			http.Error(w, "dns query parameter required", http.StatusBadRequest)
			return
		}
		var err error
		wire, err = base64.RawURLEncoding.DecodeString(param)
		if err != nil {
			wire, err = base64.URLEncoding.DecodeString(param)
		}
		if err != nil {
			http.Error(w, "invalid dns query parameter", http.StatusBadRequest)
			return
		}
	case "POST":
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if ct != "" && ct != "application/dns-message" {
			http.Error(w, "content type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		var err error
		wire, err = io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(wire) > 64*1024 {
		http.Error(w, "DNS message too large", http.StatusRequestEntityTooLarge)
		return
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(wire); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}
	resp := d.resolveDNS(msg, r.RemoteAddr, r.Host, "doh")
	out, err := resp.Pack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(out)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func (d *DNSLeaf) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"app": "dnsleaf", "ok": true, "uptime": time.Since(d.started).Truncate(time.Second).String()})
}

func (d *DNSLeaf) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(indexHTML))
}

func (d *DNSLeaf) handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logoPNG)
}

func (d *DNSLeaf) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.statsMu.Lock()
	s := d.stats
	d.statsMu.Unlock()
	sys := collectSystemStats()
	d.blockMu.RLock()
	bc := d.blockedCountLocked()
	d.blockMu.RUnlock()
	writeJSON(w, map[string]interface{}{
		"uptime":            time.Since(d.started).Truncate(time.Second).String(),
		"stats":             s,
		"blocked_count":     bc,
		"blocklist_count":   len(d.cfg.Blocklists),
		"records_count":     len(d.cfg.Records),
		"upstream_count":    len(d.cfg.Upstreams),
		"active_upstreams":  len(d.activeUpstreams()),
		"client_count":      len(d.clientList()),
		"listen":            d.cfg.Listen,
		"http":              d.cfg.HTTP,
		"cache_enabled":     d.cfg.Cache,
		"lan_only":          d.cfg.LANOnly,
		"whitelist_only":    d.cfg.WhitelistOnly,
		"resolver_disabled": d.cfg.ResolverDisabled,
		"host": map[string]interface{}{
			"hostname": sys.Hostname,
			"cpu":      sys.CPU,
			"memory":   processMemory(),
		},
	})
}

func (d *DNSLeaf) activeUpstreams() []string {
	addrs := make([]string, 0, len(d.cfg.Upstreams))
	for _, addr := range d.cfg.Upstreams {
		if !d.disabledUpstream(addr) {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func (d *DNSLeaf) clientList() []ClientInfo {
	d.clientsMu.Lock()
	defer d.clientsMu.Unlock()
	items := make([]ClientInfo, 0, len(d.clients))
	for ip, c := range d.clients {
		profileName, _, _ := d.profileForClient(ip)
		items = append(items, ClientInfo{
			IP:          ip,
			Name:        d.clientName(ip),
			Profile:     profileName,
			Allowed:     d.clientAllowed(ip),
			Whitelisted: ipInList(ip, d.cfg.Whitelist),
			LAN:         isLANIP(ip),
			Queries:     c.queries,
			Blocked:     c.blocked,
			Local:       c.local,
			Cached:      c.cached,
			Forwarded:   c.forwarded,
			Denied:      c.denied,
			Trolled:     c.trolled,
			LastSeen:    formatClientLastSeen(c.lastSeen),
		})
	}
	return items
}

func formatClientLastSeen(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	if time.Since(t) < 24*time.Hour {
		return t.Format("15:04:05")
	}
	return t.Format("2006-01-02 15:04")
}

func (d *DNSLeaf) handleRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.Records)
	case "POST":
		var rec Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rec.Host = strings.ToLower(strings.TrimSuffix(rec.Host, "."))
		rec.IP = strings.TrimSpace(rec.IP)
		rec.Value = strings.TrimSpace(rec.Value)
		rec.Note = strings.TrimSpace(rec.Note)
		rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
		if rec.Type == "" {
			rec.Type = "A"
		}
		if rec.Value == "" {
			rec.Value = rec.IP
		}
		if rec.IP == "" {
			rec.IP = rec.Value
		}
		if rec.Host == "" || rec.Value == "" {
			http.Error(w, "host and value required", 400)
			return
		}
		d.cfg.Records = append(d.cfg.Records, rec)
		writeJSON(w, rec)
	case "PUT":
		var body struct {
			OldHost string `json:"old_host"`
			OldIP   string `json:"old_ip"`
			Host    string `json:"host"`
			IP      string `json:"ip"`
			Type    string `json:"type"`
			Value   string `json:"value"`
			Note    string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(body.Host), "."))
		ip := strings.TrimSpace(body.IP)
		value := strings.TrimSpace(body.Value)
		if value == "" {
			value = ip
		}
		recType := strings.ToUpper(strings.TrimSpace(body.Type))
		if recType == "" {
			recType = "A"
		}
		if host == "" || value == "" {
			http.Error(w, "host and value required", 400)
			return
		}
		for i, rec := range d.cfg.Records {
			if rec.IP == body.OldIP && strings.EqualFold(rec.Host, body.OldHost) {
				d.cfg.Records[i] = Record{Host: host, Type: recType, Value: value, IP: value, Note: strings.TrimSpace(body.Note)}
				writeJSON(w, d.cfg.Records[i])
				return
			}
		}
		http.Error(w, "record not found", 404)
	case "DELETE":
		var rec Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for i, r := range d.cfg.Records {
			if r.IP == rec.IP && strings.EqualFold(r.Host, rec.Host) {
				d.cfg.Records = append(d.cfg.Records[:i], d.cfg.Records[i+1:]...)
				break
			}
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func recordFromRR(rr dns.RR) (Record, bool) {
	host := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
	rec := Record{}
	note := ""
	if idx := strings.Index(rr.String(), ";"); idx >= 0 {
		note = strings.TrimSpace(rr.String()[idx+1:])
	}
	switch v := rr.(type) {
	case *dns.A:
		rec = Record{Host: host, Type: "A", Value: v.A.String(), IP: v.A.String(), Note: note}
	case *dns.AAAA:
		rec = Record{Host: host, Type: "AAAA", Value: v.AAAA.String(), IP: v.AAAA.String(), Note: note}
	case *dns.CNAME:
		rec = Record{Host: host, Type: "CNAME", Value: strings.TrimSuffix(v.Target, "."), Note: note}
	case *dns.TXT:
		rec = Record{Host: host, Type: "TXT", Value: strings.Join(v.Txt, ""), Note: note}
	case *dns.MX:
		rec = Record{Host: host, Type: "MX", Value: strings.TrimSuffix(v.Mx, "."), Priority: v.Preference, Note: note}
	case *dns.SRV:
		rec = Record{Host: host, Type: "SRV", Value: strings.TrimSuffix(v.Target, "."), Priority: v.Priority, Weight: v.Weight, Port: v.Port, Note: note}
	case *dns.PTR:
		rec = Record{Host: host, Type: "PTR", Value: strings.TrimSuffix(v.Ptr, "."), Note: note}
	default:
		return Record{}, false
	}
	return rec, true
}

func (d *DNSLeaf) handleImportRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(64 * 1024 * 1024); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer file.Close()
		overwrite := strings.EqualFold(r.FormValue("overwrite"), "true") || r.FormValue("overwrite") == "1"
		imported, skipped, err := d.importRecordsFromReader(file, r.FormValue("zone"), header.Filename, overwrite)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]int{"imported": imported, "skipped": skipped})
		return
	}
	var body struct {
		Path      string `json:"path"`
		Zone      string `json:"zone"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	path := strings.TrimSpace(body.Path)
	if path == "" {
		http.Error(w, "path required", 400)
		return
	}
	path = d.runtimePath(path)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer f.Close()
	imported, skipped, err := d.importRecordsFromReader(f, body.Zone, path, body.Overwrite)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]int{"imported": imported, "skipped": skipped})
}

func (d *DNSLeaf) importRecordsFromReader(r io.Reader, zone, origin string, overwrite bool) (int, int, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(zone), origin)
	imported := 0
	skipped := 0
	seen := make(map[string]bool)
	if !overwrite {
		for _, rec := range d.cfg.Records {
			seen[strings.ToLower(rec.Host)+"|"+strings.ToUpper(rec.Type)+"|"+rec.Value] = true
		}
	}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rec, supported := recordFromRR(rr)
		if !supported {
			skipped++
			continue
		}
		key := strings.ToLower(rec.Host) + "|" + strings.ToUpper(rec.Type) + "|" + rec.Value
		if !overwrite && seen[key] {
			skipped++
			continue
		}
		d.cfg.Records = append(d.cfg.Records, rec)
		seen[key] = true
		imported++
	}
	if err := zp.Err(); err != nil {
		return 0, 0, err
	}
	return imported, skipped, nil
}

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

func (d *DNSLeaf) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		items := make([]map[string]interface{}, 0, len(d.cfg.Upstreams))
		for _, addr := range d.cfg.Upstreams {
			items = append(items, map[string]interface{}{"address": addr, "enabled": !d.disabledUpstream(addr)})
		}
		writeJSON(w, items)
	case "POST":
		var body struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		addr := strings.TrimSpace(body.Address)
		if addr == "" {
			http.Error(w, "address required", 400)
			return
		}
		if !strings.Contains(addr, ":") {
			addr = addr + ":53"
		}
		d.cfg.Upstreams = append(d.cfg.Upstreams, addr)
		writeJSON(w, map[string]string{"address": addr})
	case "PATCH":
		var body struct {
			Address string `json:"address"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		addr := strings.TrimSpace(body.Address)
		if addr == "" {
			http.Error(w, "address required", 400)
			return
		}
		next := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != addr {
				next = append(next, item)
			}
		}
		if !body.Enabled {
			next = append(next, addr)
		}
		d.cfg.DisabledUpstreams = next
		writeJSON(w, map[string]interface{}{"address": addr, "enabled": body.Enabled})
	case "DELETE":
		var body struct {
			Address string `json:"address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for i, a := range d.cfg.Upstreams {
			if a == body.Address {
				d.cfg.Upstreams = append(d.cfg.Upstreams[:i], d.cfg.Upstreams[i+1:]...)
				break
			}
		}
		next := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != body.Address {
				next = append(next, item)
			}
		}
		d.cfg.DisabledUpstreams = next
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.clientList())
	case "PATCH":
		var body struct {
			IP          string `json:"ip"`
			Name        string `json:"name"`
			Profile     string `json:"profile"`
			Whitelisted *bool  `json:"whitelisted"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ip := strings.TrimSpace(body.IP)
		if ip == "" {
			http.Error(w, "ip required", 400)
			return
		}
		if d.cfg.ClientNames == nil {
			d.cfg.ClientNames = map[string]string{}
		}
		name := strings.TrimSpace(body.Name)
		if name == "" {
			delete(d.cfg.ClientNames, ip)
		} else {
			d.cfg.ClientNames[ip] = name
		}
		if body.Whitelisted != nil {
			next := d.cfg.Whitelist[:0]
			for _, item := range d.cfg.Whitelist {
				if item != ip {
					next = append(next, item)
				}
			}
			if *body.Whitelisted {
				next = append(next, ip)
			}
			d.cfg.Whitelist = next
		}
		if d.cfg.ClientProfiles == nil {
			d.cfg.ClientProfiles = map[string]string{}
		}
		profile := strings.TrimSpace(body.Profile)
		if profile == "" {
			delete(d.cfg.ClientProfiles, ip)
		} else {
			if _, ok := d.cfg.Profiles[profile]; !ok {
				http.Error(w, "profile not found", 404)
				return
			}
			d.cfg.ClientProfiles[ip] = profile
		}
		profileName, _, _ := d.profileForClient(ip)
		writeJSON(w, map[string]interface{}{"ip": ip, "name": d.clientName(ip), "profile": profileName, "whitelisted": ipInList(ip, d.cfg.Whitelist)})
	case "DELETE":
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ip := strings.TrimSpace(body.IP)
		if ip == "" {
			http.Error(w, "ip required", 400)
			return
		}
		d.clientsMu.Lock()
		delete(d.clients, ip)
		d.clientsMu.Unlock()
		if d.cfg.ClientNames != nil {
			delete(d.cfg.ClientNames, ip)
		}
		if d.cfg.ClientProfiles != nil {
			delete(d.cfg.ClientProfiles, ip)
		}
		next := d.cfg.Whitelist[:0]
		for _, item := range d.cfg.Whitelist {
			if item != ip {
				next = append(next, item)
			}
		}
		d.cfg.Whitelist = next
		d.requestPersistentSave()
		writeJSON(w, map[string]interface{}{"removed": ip})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleClearDeniedClients(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	removed := 0
	d.clientsMu.Lock()
	for ip := range d.clients {
		if !d.clientAllowed(ip) {
			delete(d.clients, ip)
			removed++
		}
	}
	d.clientsMu.Unlock()
	d.requestPersistentSave()
	writeJSON(w, map[string]int{"removed": removed})
}

func (d *DNSLeaf) handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, map[string]interface{}{"profiles": d.cfg.Profiles, "default_profile": d.cfg.DefaultProfile})
	case "POST":
		var body struct {
			OldName        string        `json:"old_name"`
			Name           string        `json:"name"`
			DefaultProfile bool          `json:"default_profile"`
			Profile        ClientProfile `json:"profile"`
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
		old := strings.TrimSpace(body.OldName)
		if old == "" {
			old = name
		}
		body.Profile.Allowed = cleanRules(body.Profile.Allowed)
		body.Profile.Blocked = cleanRules(body.Profile.Blocked)
		body.Profile.Blocklists = cleanNames(body.Profile.Blocklists)
		if d.cfg.Profiles == nil {
			d.cfg.Profiles = map[string]ClientProfile{}
		}
		if old != name {
			if _, exists := d.cfg.Profiles[name]; exists {
				http.Error(w, "profile already exists", 409)
				return
			}
			delete(d.cfg.Profiles, old)
			for ip, profile := range d.cfg.ClientProfiles {
				if profile == old {
					d.cfg.ClientProfiles[ip] = name
				}
			}
			if d.cfg.DefaultProfile == old {
				d.cfg.DefaultProfile = name
			}
		}
		d.cfg.Profiles[name] = body.Profile
		if body.DefaultProfile {
			d.cfg.DefaultProfile = name
		}
		writeJSON(w, map[string]interface{}{"name": name, "profile": body.Profile, "default_profile": d.cfg.DefaultProfile})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleProfilePath(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/profiles/") {
		http.NotFound(w, r)
		return
	}
	name, err := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/api/profiles/"))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		http.Error(w, "profile required", 400)
		return
	}
	if r.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	if name == "off" || name == d.cfg.DefaultProfile {
		http.Error(w, "cannot remove built-in or default profile", 400)
		return
	}
	if _, ok := d.cfg.Profiles[name]; !ok {
		http.Error(w, "profile not found", 404)
		return
	}
	delete(d.cfg.Profiles, name)
	for ip, profile := range d.cfg.ClientProfiles {
		if profile == name {
			delete(d.cfg.ClientProfiles, ip)
		}
	}
	w.WriteHeader(204)
}

func (d *DNSLeaf) handleClientProfilePath(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/clients/") || !strings.HasSuffix(r.URL.Path, "/profile") {
		http.NotFound(w, r)
		return
	}
	part := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/profile")
	ip, err := url.PathUnescape(part)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		http.Error(w, "ip required", 400)
		return
	}
	switch r.Method {
	case "GET":
		profileName, _, _ := d.profileForClient(ip)
		writeJSON(w, map[string]string{"ip": ip, "profile": profileName})
	case "POST":
		var body struct {
			Profile string `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		profile := strings.TrimSpace(body.Profile)
		if d.cfg.ClientProfiles == nil {
			d.cfg.ClientProfiles = map[string]string{}
		}
		if profile == "" {
			delete(d.cfg.ClientProfiles, ip)
		} else {
			if _, ok := d.cfg.Profiles[profile]; !ok {
				http.Error(w, "profile not found", 404)
				return
			}
			d.cfg.ClientProfiles[ip] = profile
		}
		profileName, _, _ := d.profileForClient(ip)
		writeJSON(w, map[string]string{"ip": ip, "profile": profileName})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, map[string]interface{}{
			"listen":                 d.cfg.Listen,
			"http":                   d.cfg.HTTP,
			"https":                  d.cfg.HTTPS,
			"tls_cert_file":          d.cfg.TLSCert,
			"tls_key_file":           d.cfg.TLSKey,
			"portal_host":            d.cfg.PortalHost,
			"portal_ip":              d.cfg.PortalIP,
			"upstreams":              d.cfg.Upstreams,
			"disabled_upstreams":     d.cfg.DisabledUpstreams,
			"records":                d.cfg.Records,
			"blocked":                d.cfg.Blocked,
			"blocked_ips":            d.cfg.BlockedIPs,
			"allowed":                d.cfg.Allowed,
			"blocklist_file":         d.cfg.Blocklist,
			"blocklists":             d.cfg.Blocklists,
			"cache_enabled":          d.cfg.Cache,
			"cache_size":             d.cfg.CacheSize,
			"cache_ttl_seconds":      d.cfg.CacheTTL,
			"lan_only":               d.cfg.LANOnly,
			"whitelist_only":         d.cfg.WhitelistOnly,
			"resolver_disabled":      d.cfg.ResolverDisabled,
			"whitelist":              d.cfg.Whitelist,
			"direct_override":        d.cfg.DirectOverride,
			"direct_override_to":     d.cfg.DirectOverrideTo,
			"troll_mode":             d.cfg.TrollMode,
			"troll_hosts":            d.cfg.TrollHosts,
			"troll_ipv4":             d.cfg.TrollIPv4,
			"troll_ipv6":             d.cfg.TrollIPv6,
			"http_proxy_enabled":     d.cfg.HTTPProxyEnabled,
			"http_proxy":             d.cfg.HTTPProxy,
			"socks_proxy_enabled":    d.cfg.SOCKSProxyEnabled,
			"socks_proxy":            d.cfg.SOCKSProxy,
			"client_names":           d.cfg.ClientNames,
			"client_profiles":        d.cfg.ClientProfiles,
			"default_profile":        d.cfg.DefaultProfile,
			"profiles":               d.cfg.Profiles,
			"scheduled_rules":        d.cfg.ScheduledRules,
			"dot":                    d.cfg.DoT,
			"rate_limit":             d.cfg.RateLimit,
			"anomaly":                d.cfg.Anomaly,
			"conditional_forwarding": d.cfg.ConditionalForward,
			"dhcp_leases_file":       d.cfg.DHCPLeasesFile,
			"upstream_health":        d.cfg.UpstreamHealth,
			"auth_enabled":           d.cfg.Auth.Enabled,
		})
	case "PUT":
		var body struct {
			Listen             string                   `json:"listen"`
			HTTP               string                   `json:"http"`
			Cache              bool                     `json:"cache_enabled"`
			CacheSize          int                      `json:"cache_size"`
			CacheTTL           int                      `json:"cache_ttl_seconds"`
			Blocklist          string                   `json:"blocklist_file"`
			LANOnly            bool                     `json:"lan_only"`
			WhitelistOnly      bool                     `json:"whitelist_only"`
			ResolverDisabled   bool                     `json:"resolver_disabled"`
			Whitelist          []string                 `json:"whitelist"`
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
			HTTPS              string                   `json:"https"`
			TLSCert            string                   `json:"tls_cert_file"`
			TLSKey             string                   `json:"tls_key_file"`
			PortalHost         string                   `json:"portal_host"`
			PortalIP           string                   `json:"portal_ip"`
			DoT                string                   `json:"dot"`
			DHCPLeasesFile     string                   `json:"dhcp_leases_file"`
			ClientProfiles     map[string]string        `json:"client_profiles"`
			DefaultProfile     string                   `json:"default_profile"`
			Profiles           map[string]ClientProfile `json:"profiles"`
			ScheduledRules     []ScheduledRule          `json:"scheduled_rules"`
			RateLimit          RateLimitConfig          `json:"rate_limit"`
			Anomaly            AnomalyConfig            `json:"anomaly"`
			ConditionalForward []ConditionalForward     `json:"conditional_forwarding"`
			UpstreamHealth     UpstreamHealthConfig     `json:"upstream_health"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if strings.TrimSpace(body.Listen) != "" {
			d.cfg.Listen = strings.TrimSpace(body.Listen)
		}
		if strings.TrimSpace(body.HTTP) != "" {
			d.cfg.HTTP = strings.TrimSpace(body.HTTP)
		}
		d.cfg.HTTPS = strings.TrimSpace(body.HTTPS)
		d.cfg.DoT = strings.TrimSpace(body.DoT)
		d.cfg.TLSCert = strings.TrimSpace(body.TLSCert)
		d.cfg.TLSKey = strings.TrimSpace(body.TLSKey)
		if strings.TrimSpace(body.PortalHost) != "" {
			d.cfg.PortalHost = strings.TrimSpace(body.PortalHost)
		}
		if strings.TrimSpace(body.PortalIP) != "" {
			d.cfg.PortalIP = strings.TrimSpace(body.PortalIP)
		}
		d.cfg.Cache = body.Cache
		if body.CacheSize > 0 {
			d.cfg.CacheSize = body.CacheSize
		}
		if body.CacheTTL > 0 {
			d.cfg.CacheTTL = body.CacheTTL
		}
		d.cfg.Blocklist = strings.TrimSpace(body.Blocklist)
		d.cfg.DHCPLeasesFile = strings.TrimSpace(body.DHCPLeasesFile)
		if body.ClientProfiles != nil {
			d.cfg.ClientProfiles = body.ClientProfiles
		}
		if strings.TrimSpace(body.DefaultProfile) != "" {
			d.cfg.DefaultProfile = strings.TrimSpace(body.DefaultProfile)
		}
		if body.Profiles != nil {
			d.cfg.Profiles = body.Profiles
		}
		if body.ScheduledRules != nil {
			d.cfg.ScheduledRules = body.ScheduledRules
		}
		if body.RateLimit.Queries > 0 {
			d.cfg.RateLimit = body.RateLimit
		}
		if body.Anomaly.Hits > 0 {
			d.cfg.Anomaly = body.Anomaly
		}
		if body.ConditionalForward != nil {
			d.cfg.ConditionalForward = body.ConditionalForward
		}
		if body.UpstreamHealth.Interval > 0 {
			d.cfg.UpstreamHealth = body.UpstreamHealth
		}
		d.cfg.LANOnly = body.LANOnly
		d.cfg.WhitelistOnly = body.WhitelistOnly
		d.cfg.ResolverDisabled = body.ResolverDisabled
		d.cfg.DirectOverride = body.DirectOverride
		d.cfg.DirectOverrideTo = strings.TrimSpace(body.DirectOverrideTo)
		d.cfg.TrollMode = body.TrollMode
		d.cfg.TrollHosts = cleanStringList(body.TrollHosts)
		if len(d.cfg.TrollHosts) == 0 {
			d.cfg.TrollHosts = []string{"4chan.org", "neopets.com", "homestarrunner.com", "theonion.com", "archive.org", "wikipedia.org"}
		}
		d.cfg.TrollIPv4 = cleanStringList(body.TrollIPv4)
		d.cfg.TrollIPv6 = cleanStringList(body.TrollIPv6)
		d.cfg.HTTPProxyEnabled = body.HTTPProxyEnabled
		d.cfg.HTTPProxy = strings.TrimSpace(body.HTTPProxy)
		d.cfg.SOCKSProxyEnabled = body.SOCKSProxyEnabled
		d.cfg.SOCKSProxy = strings.TrimSpace(body.SOCKSProxy)
		d.cfg.Whitelist = make([]string, 0, len(body.Whitelist))
		for _, item := range body.Whitelist {
			item = strings.TrimSpace(item)
			if item != "" {
				d.cfg.Whitelist = append(d.cfg.Whitelist, item)
			}
		}
		ensureBuiltinProfiles(&d.cfg)
		writeJSON(w, d.cfg)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleSelfSignedTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		CommonName   string `json:"common_name"`
		Host         string `json:"host"`
		DNSNames     string `json:"dns_names"`
		IPAddresses  string `json:"ip_addresses"`
		IP           string `json:"ip"`
		Organization string `json:"organization"`
		Days         int    `json:"days"`
		KeyType      string `json:"key_type"`
		Cert         string `json:"cert"`
		Key          string `json:"key"`
		HTTPS        string `json:"https"`
		IsCA         bool   `json:"is_ca"`
		Apply        bool   `json:"apply"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	host := strings.TrimSuffix(strings.TrimSpace(body.CommonName), ".")
	if host == "" {
		host = strings.TrimSuffix(strings.TrimSpace(body.Host), ".")
	}
	if host == "" {
		host = "dns.leaf"
	}
	dnsNames := cleanDNSNames(append(splitList(body.DNSNames), host))
	ipStrings := splitList(body.IPAddresses)
	if strings.TrimSpace(body.IP) != "" {
		ipStrings = append(ipStrings, body.IP)
	}
	ips, err := parseIPList(ipStrings)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if len(dnsNames) == 0 && len(ips) == 0 {
		http.Error(w, "at least one DNS or IP subject alternative name is required", 400)
		return
	}
	certPath := strings.TrimSpace(body.Cert)
	keyPath := strings.TrimSpace(body.Key)
	if certPath == "" {
		certPath = "certs/dnsleaf-cert.pem"
	}
	if keyPath == "" {
		keyPath = "certs/dnsleaf-key.pem"
	}
	certFile := d.runtimePath(certPath)
	keyFile := d.runtimePath(keyPath)
	days := body.Days
	if days <= 0 {
		days = 398
	}
	if days > 3650 {
		days = 3650
	}
	priv, publicKey, keyBlock, err := generateTLSKey(body.KeyType)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{strings.TrimSpace(body.Organization)},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	if strings.TrimSpace(body.Organization) == "" {
		template.Subject.Organization = nil
	}
	if body.IsCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	der, err := x509.CreateCertificate(crand.Reader, &template, &template, publicKey, priv)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.MkdirAll(filepathDir(certFile), 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := os.MkdirAll(filepathDir(keyFile), 0700); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := writePEMFile(certFile, 0644, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := writePEMFile(keyFile, 0600, keyBlock); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	applied := body.Apply
	if applied {
		d.cfg.PortalHost = host
		if len(ips) > 0 {
			d.cfg.PortalIP = ips[0].String()
		}
		d.cfg.TLSCert = certPath
		d.cfg.TLSKey = keyPath
		if strings.TrimSpace(body.HTTPS) != "" {
			d.cfg.HTTPS = strings.TrimSpace(body.HTTPS)
		}
	}
	writeJSON(w, map[string]interface{}{"cert": certPath, "key": keyPath, "host": host, "https": d.cfg.HTTPS, "dns_names": dnsNames, "ip_addresses": ipStrings, "applied": applied, "is_ca": body.IsCA, "days": days})
}

func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func cleanStringList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func cleanDNSNames(names []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || net.ParseIP(name) != nil || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func parseIPList(items []string) ([]net.IP, error) {
	seen := map[string]bool{}
	out := make([]net.IP, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP SAN: %s", item)
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out, nil
}

func generateTLSKey(keyType string) (interface{}, interface{}, *pem.Block, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "", "ecdsa", "ecdsa-p256", "p256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, nil, err
		}
		return key, &key.PublicKey, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	case "rsa-2048", "rsa2048":
		return generateRSAKey(2048)
	case "rsa-3072", "rsa3072":
		return generateRSAKey(3072)
	case "rsa-4096", "rsa4096":
		return generateRSAKey(4096)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func generateRSAKey(bits int) (interface{}, interface{}, *pem.Block, error) {
	key, err := rsa.GenerateKey(crand.Reader, bits)
	if err != nil {
		return nil, nil, nil, err
	}
	return key, &key.PublicKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}, nil
}

func filepathDir(path string) string {
	i := strings.LastIndexAny(path, `/\`)
	if i <= 0 {
		return "."
	}
	return path[:i]
}

func writePEMFile(path string, perm os.FileMode, block *pem.Block) error {
	var data bytes.Buffer
	if err := pem.Encode(&data, block); err != nil {
		return err
	}
	return atomicWriteFile(path, data.Bytes(), perm)
}

type systemStats struct {
	Hostname string
	Temp     string
	CPU      string
	Memory   string
}

var cpuSample struct {
	sync.Mutex
	total uint64
	idle  uint64
	seen  bool
}

var processCPUSample struct {
	sync.Mutex
	cpuSeconds float64
	wall       time.Time
	seen       bool
}

func collectSystemStats() systemStats {
	host, _ := os.Hostname()
	s := systemStats{Hostname: host, Temp: "n/a", CPU: "n/a", Memory: "n/a"}
	switch runtime.GOOS {
	case "linux":
		s.Temp = linuxTemp()
		s.CPU = processCPUPercent()
		s.Memory = linuxMemory()
	case "windows":
		s.Temp = windowsTemp()
		s.CPU = processCPUPercent()
		s.Memory = windowsMemory()
	}
	return s
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

func (d *DNSLeaf) handleLog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		d.logMu.Lock()
		logCopy := make([]QueryEntry, len(d.log))
		copy(logCopy, d.log)
		d.logMu.Unlock()
		writeJSON(w, logCopy)
	case "DELETE":
		d.logMu.Lock()
		d.log = d.log[:0]
		d.logMu.Unlock()
		d.requestPersistentSave()
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleServerLog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		d.serverMu.Lock()
		items := append([]string(nil), d.serverLog...)
		d.serverMu.Unlock()
		writeJSON(w, items)
	case "DELETE":
		d.serverMu.Lock()
		d.serverLog = d.serverLog[:0]
		d.serverMu.Unlock()
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := d.refreshBlocklistTarget(body.Target); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d.blockMu.RLock()
	bc := d.blockedCountLocked()
	d.blockMu.RUnlock()
	writeJSON(w, map[string]interface{}{"status": "ok", "blocked_count": bc})
}

func (d *DNSLeaf) handleGravityStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		Target string `json:"target"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if err := d.startGravity(body.Target); err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	writeJSON(w, d.gravitySnapshot())
}

func (d *DNSLeaf) handleGravityProgress(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", 405)
		return
	}
	writeJSON(w, d.gravitySnapshot())
}

func (d *DNSLeaf) handleSession(w http.ResponseWriter, r *http.Request) {
	s, ok := d.sessionFromRequest(r)
	if !ok {
		writeJSON(w, map[string]interface{}{"authenticated": false, "auth_enabled": d.cfg.Auth.Enabled})
		return
	}
	writeJSON(w, map[string]interface{}{"authenticated": true, "auth_enabled": d.cfg.Auth.Enabled, "username": s.Username, "role": s.Role})
}

const loginWindow = 15 * time.Minute
const loginBlock = time.Minute
const loginMaxFailures = 8

func (d *DNSLeaf) loginAllowed(client string) (bool, time.Duration) {
	now := time.Now()
	d.loginMu.Lock()
	defer d.loginMu.Unlock()
	attempt := d.loginAttempts[client]
	if !attempt.FirstFailed.IsZero() && now.Sub(attempt.FirstFailed) >= loginWindow {
		delete(d.loginAttempts, client)
		return true, 0
	}
	if now.Before(attempt.BlockedTill) {
		return false, time.Until(attempt.BlockedTill)
	}
	return true, 0
}

func (d *DNSLeaf) noteLoginFailure(client string) {
	now := time.Now()
	d.loginMu.Lock()
	defer d.loginMu.Unlock()
	attempt := d.loginAttempts[client]
	if attempt.FirstFailed.IsZero() || now.Sub(attempt.FirstFailed) >= loginWindow {
		attempt = loginAttempt{FirstFailed: now}
	}
	attempt.Failures++
	if attempt.Failures >= loginMaxFailures {
		attempt.BlockedTill = now.Add(loginBlock)
	}
	d.loginAttempts[client] = attempt
}

func (d *DNSLeaf) clearLoginFailures(client string) {
	d.loginMu.Lock()
	delete(d.loginAttempts, client)
	d.loginMu.Unlock()
}

func (d *DNSLeaf) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		client := normalizeClientIP(r.RemoteAddr)
		if allowed, wait := d.loginAllowed(client); !allowed {
			seconds := int(wait.Seconds())
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			http.Error(w, "too many login attempts", http.StatusTooManyRequests)
			return
		}
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&body); err != nil {
			d.noteLoginFailure(client)
			http.Error(w, err.Error(), 400)
			return
		}
		user, ok := d.findUser(strings.TrimSpace(body.Username))
		if !ok || !verifyPassword(body.Password, user.PasswordHash) {
			d.noteLoginFailure(client)
			http.Error(w, "invalid username or password", http.StatusUnauthorized)
			return
		}
		d.clearLoginFailures(client)
		token := randomToken(32)
		expires := time.Now().Add(12 * time.Hour)
		d.sessMu.Lock()
		d.sessions[token] = Session{Username: user.Username, Role: user.Role, Expires: expires}
		d.sessMu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "dnsleaf_session",
			Value:    token,
			Path:     "/",
			Expires:  expires,
			HttpOnly: true,
			Secure:   r.TLS != nil || strings.TrimSpace(d.cfg.HTTPS) != "",
			SameSite: http.SameSiteStrictMode,
		})
		writeJSON(w, map[string]interface{}{"authenticated": true, "username": user.Username, "role": user.Role})
	case "DELETE":
		cookie, err := r.Cookie("dnsleaf_session")
		if err == nil {
			d.sessMu.Lock()
			delete(d.sessions, cookie.Value)
			d.sessMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "dnsleaf_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || strings.TrimSpace(d.cfg.HTTPS) != "", SameSite: http.SameSiteStrictMode})
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users := make([]map[string]string, 0, len(d.cfg.Auth.Users))
		for _, user := range d.cfg.Auth.Users {
			users = append(users, map[string]string{"username": user.Username, "role": user.Role, "created_at": user.CreatedAt})
		}
		writeJSON(w, users)
	case "POST":
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		username := strings.TrimSpace(body.Username)
		role := strings.TrimSpace(body.Role)
		if role == "" {
			role = "viewer"
		}
		if !validUsername(username) || body.Password == "" || len(body.Password) > 4096 || (role != "admin" && role != "viewer") {
			http.Error(w, "username, password, and valid role required", 400)
			return
		}
		if _, exists := d.findUser(username); exists {
			http.Error(w, "user exists", 409)
			return
		}
		d.cfg.Auth.Users = append(d.cfg.Auth.Users, UserAuth{
			Username:     username,
			PasswordHash: passwordHash(body.Password),
			Role:         role,
			CreatedAt:    time.Now().Format(time.RFC3339),
		})
		writeJSON(w, map[string]string{"username": username, "role": role})
	case "PATCH":
		var body struct {
			Username    string `json:"username"`
			NewUsername string `json:"new_username"`
			Password    string `json:"password"`
			Role        string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		username := strings.TrimSpace(body.Username)
		if !validUsername(username) {
			http.Error(w, "valid username required", 400)
			return
		}
		if body.NewUsername != "" && !validUsername(strings.TrimSpace(body.NewUsername)) {
			http.Error(w, "new username is invalid", 400)
			return
		}
		if body.Role != "" && body.Role != "admin" && body.Role != "viewer" {
			http.Error(w, "role must be admin or viewer", 400)
			return
		}
		if len(body.Password) > 4096 {
			http.Error(w, "password is too long", 400)
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username != username {
				continue
			}
			newUsername := strings.TrimSpace(body.NewUsername)
			newRole := user.Role
			if body.Role != "" {
				newRole = body.Role
			}
			if user.Role == "admin" && newRole != "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
				http.Error(w, "cannot demote the last administrator", 400)
				return
			}
			if newUsername != "" && newUsername != username {
				for _, existing := range d.cfg.Auth.Users {
					if strings.EqualFold(existing.Username, newUsername) {
						http.Error(w, "username already exists", 409)
						return
					}
				}
				d.cfg.Auth.Users[i].Username = newUsername
			}
			if body.Role == "admin" || body.Role == "viewer" {
				d.cfg.Auth.Users[i].Role = body.Role
			}
			if body.Password != "" {
				d.cfg.Auth.Users[i].PasswordHash = passwordHash(body.Password)
			}
			updated := d.cfg.Auth.Users[i]
			d.revokeUserSessions(user.Username)
			writeJSON(w, map[string]string{"username": updated.Username, "role": updated.Role})
			return
		}
		http.Error(w, "user not found", 404)
	case "DELETE":
		var body struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		username := strings.TrimSpace(body.Username)
		for i, user := range d.cfg.Auth.Users {
			if user.Username != username {
				continue
			}
			if len(d.cfg.Auth.Users) <= 1 {
				http.Error(w, "cannot remove the last user", 400)
				return
			}
			if user.Role == "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
				http.Error(w, "cannot remove the last administrator", 400)
				return
			}
			d.cfg.Auth.Users = append(d.cfg.Auth.Users[:i], d.cfg.Auth.Users[i+1:]...)
			d.revokeUserSessions(user.Username)
			w.WriteHeader(204)
			return
		}
		http.Error(w, "user not found", 404)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (d *DNSLeaf) handleCLI(args []string) bool {
	if len(args) == 0 {
		return false
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

func (d *DNSLeaf) serveHTTPProxy(addr string) error {
	srv := newHTTPServer(addr, http.HandlerFunc(d.handleHTTPProxy), log.New(serverLogWriter{dad: d}, "", 0))
	d.registerHTTPServer(srv)
	d.consoleLogf("[DNSLeaf] HTTP proxy listening on %s", addr)
	return srv.ListenAndServe()
}

func (d *DNSLeaf) handleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	clientIP := normalizeClientIP(r.RemoteAddr)
	d.cfgMu.RLock()
	allowed := d.clientAllowed(clientIP)
	d.cfgMu.RUnlock()
	if !allowed {
		http.Error(w, "proxy access denied", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		d.handleHTTPConnect(w, r)
		return
	}
	target := new(http.Request)
	*target = *r
	target.RequestURI = ""
	target.URL = cloneURL(r.URL)
	if !target.URL.IsAbs() {
		target.URL.Scheme = "http"
		target.URL.Host = r.Host
	}
	target.Header = cloneHeader(r.Header)
	target.Header.Del("Proxy-Connection")
	target.Header.Del("Proxy-Authenticate")
	target.Header.Del("Proxy-Authorization")
	resp, err := proxyTransport.RoundTrip(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (d *DNSLeaf) handleHTTPConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unavailable", http.StatusInternalServerError)
		return
	}
	target, err := net.DialTimeout("tcp", ensurePort(r.Host, "443"), 15*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		target.Close()
		return
	}
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	copyBoth(client, target)
}

func (d *DNSLeaf) serveSOCKSProxy(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	d.registerProxyListener(ln)
	d.consoleLogf("[DNSLeaf] SOCKS5 proxy listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go d.handleSOCKSConn(conn)
	}
}

func (d *DNSLeaf) handleSOCKSConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	clientIP := normalizeClientIP(conn.RemoteAddr().String())
	d.cfgMu.RLock()
	allowed := d.clientAllowed(clientIP)
	d.cfgMu.RUnlock()
	if !allowed {
		return
	}
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	conn.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 5 || req[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	host := ""
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 3:
		n, err := br.ReadByte()
		if err != nil {
			return
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IP(b).String()
	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 15*time.Second)
	if err != nil {
		conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	_ = conn.SetDeadline(time.Time{})
	conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	copyBoth(&bufferedConn{Conn: conn, r: br}, target)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func cloneURL(u *url.URL) *url.URL {
	cp := *u
	return &cp
}

func cloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	copyHeader(out, h)
	return out
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func ensurePort(host, def string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, def)
}

func copyBoth(a, b net.Conn) {
	var once sync.Once
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	go func() {
		io.Copy(a, b)
		once.Do(closeBoth)
	}()
	io.Copy(b, a)
	once.Do(closeBoth)
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
		return
	}
	d.dnsServers = append(d.dnsServers, server)
	d.serversMu.Unlock()
	d.stopMu.Unlock()
}

func (d *DNSLeaf) registerHTTPServer(server *http.Server) {
	d.stopMu.Lock()
	d.serversMu.Lock()
	if d.stopped {
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(ctx)
		cancel()
		return
	}
	d.httpServers = append(d.httpServers, server)
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
		proxyListeners := append([]net.Listener(nil), d.proxyListeners...)
		d.serversMu.Unlock()
		d.stopMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for _, server := range dnsServers {
			_ = server.ShutdownContext(ctx)
		}
		for _, server := range httpServers {
			_ = server.Shutdown(ctx)
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
	dns.HandleFunc(".", d.HandleDNS)

	udpServer := &dns.Server{Addr: cfg.Listen, Net: "udp"}
	tcpServer := &dns.Server{Addr: cfg.Listen, Net: "tcp"}
	d.registerDNSServer(udpServer)
	d.registerDNSServer(tcpServer)

	errCh := make(chan error, 6)
	go func() {
		d.consoleLogf("[DNSLeaf] DNS listening on %s (UDP)", cfg.Listen)
		if err := udpServer.ListenAndServe(); err != nil && !d.isStopping() {
			errCh <- fmt.Errorf("UDP: %w", err)
		}
	}()
	go func() {
		d.consoleLogf("[DNSLeaf] DNS listening on %s (TCP)", cfg.Listen)
		if err := tcpServer.ListenAndServe(); err != nil && !d.isStopping() {
			errCh <- fmt.Errorf("TCP: %w", err)
		}
	}()
	if cfg.DoT != "" && cfg.TLSCert != "" && cfg.TLSKey != "" {
		dotServer := &dns.Server{Addr: cfg.DoT, Net: "tcp-tls", TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		dotServer.TLSConfig.Certificates = make([]tls.Certificate, 1)
		cert, err := tls.LoadX509KeyPair(d.runtimePath(cfg.TLSCert), d.runtimePath(cfg.TLSKey))
		if err != nil {
			d.consoleLogf("[DNSLeaf] DoT TLS error: %v", err)
		} else {
			d.registerDNSServer(dotServer)
			dotServer.TLSConfig.Certificates[0] = cert
			go func() {
				d.consoleLogf("[DNSLeaf] DNS-over-TLS listening on %s", cfg.DoT)
				if err := dotServer.ListenAndServe(); err != nil && !d.isStopping() {
					errCh <- fmt.Errorf("DoT: %w", err)
				}
			}()
		}
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
	mux.HandleFunc("/api/server-log", d.handleServerLog)
	mux.HandleFunc("/api/reload", d.handleReload)
	mux.HandleFunc("/api/gravity/start", d.handleGravityStart)
	mux.HandleFunc("/api/gravity/progress", d.handleGravityProgress)
	mux.HandleFunc("/api/settings", d.handleSettings)
	mux.HandleFunc("/api/tls/selfsigned", d.handleSelfSignedTLS)
	mux.HandleFunc("/api/users", d.handleUsers)

	handler := d.configGuard(d.requireAuth(mux))
	httpServer := newHTTPServer(cfg.HTTP, handler, log.New(serverLogWriter{dad: d}, "", 0))
	d.registerHTTPServer(httpServer)
	go func() {
		d.consoleLogf("[DNSLeaf] Web UI at %s or %s", webURL(cfg.HTTP), portalURL(cfg.PortalHost, cfg.HTTPS, cfg.HTTP))
		if err := httpServer.ListenAndServe(); err != nil && !d.isStopping() {
			errCh <- fmt.Errorf("HTTP: %w", err)
		}
	}()
	if cfg.HTTPS != "" && cfg.TLSCert != "" && cfg.TLSKey != "" {
		httpsServer := newHTTPServer(cfg.HTTPS, handler, log.New(serverLogWriter{dad: d}, "", 0))
		d.registerHTTPServer(httpsServer)
		go func() {
			d.consoleLogf("[DNSLeaf] HTTPS Web UI at %s or %s", webURL(cfg.HTTPS), portalURL(cfg.PortalHost, cfg.HTTPS, cfg.HTTP))
			if err := httpsServer.ListenAndServeTLS(d.runtimePath(cfg.TLSCert), d.runtimePath(cfg.TLSKey)); err != nil && !d.isStopping() {
				errCh <- fmt.Errorf("HTTPS: %w", err)
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
	d.consoleLogf("[DNSLeaf] ready")

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

func main() {
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
