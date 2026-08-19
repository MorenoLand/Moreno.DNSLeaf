package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func versionedAPIHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/api/v1"
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			clone := r.Clone(r.Context())
			clone.URL.Path = "/api" + strings.TrimPrefix(r.URL.Path, prefix)
			clone.URL.RawPath = ""
			next.ServeHTTP(w, clone)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (d *DNSLeaf) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"app": "dnsleaf", "ok": true, "uptime": time.Since(d.started).Truncate(time.Second).String()})
}

func (d *DNSLeaf) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if d.isStopping() {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]interface{}{"app": "dnsleaf", "ok": false, "status": "stopping"})
		return
	}
	writeJSON(w, map[string]interface{}{"app": "dnsleaf", "ok": true, "status": "alive", "uptime": time.Since(d.started).Truncate(time.Second).String()})
}

func (d *DNSLeaf) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.readyMu.RLock()
	dnsListeners := d.dnsReady
	httpListeners := d.httpReady
	startupErr := d.startupErr
	d.readyMu.RUnlock()
	d.cfgMu.RLock()
	resolverDisabled := d.cfg.ResolverDisabled
	activeUpstreams := len(d.activeUpstreams())
	d.cfgMu.RUnlock()
	ready := !d.isStopping() && startupErr == "" && dnsListeners >= 2 && httpListeners >= 1 && (resolverDisabled || activeUpstreams > 0)
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSONStatus(w, status, map[string]interface{}{"app": "dnsleaf", "ready": ready, "dns_listeners": dnsListeners, "http_listeners": httpListeners, "active_upstreams": activeUpstreams, "startup_error": startupErr})
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
		"uptime":                    time.Since(d.started).Truncate(time.Second).String(),
		"persistence_error":         d.persistenceError(),
		"stats":                     s,
		"blocked_count":             bc,
		"blocklist_count":           len(d.cfg.Blocklists),
		"records_count":             len(d.cfg.Records),
		"upstream_count":            len(d.cfg.Upstreams) + len(d.cfg.UpstreamEndpoints),
		"active_upstreams":          len(d.activeUpstreams()),
		"client_count":              len(d.clientList()),
		"listen":                    d.cfg.Listen,
		"http":                      d.cfg.HTTP,
		"cache_enabled":             d.cfg.Cache,
		"strip_ecs":                 d.cfg.StripECS,
		"query_log_enabled":         d.cfg.QueryLogEnabled,
		"query_log_retention_hours": d.cfg.QueryLogRetention,
		"anonymize_client_ips":      d.cfg.AnonymizeClientIPs,
		"lan_only":                  d.cfg.LANOnly,
		"whitelist_only":            d.cfg.WhitelistOnly,
		"resolver_disabled":         d.cfg.ResolverDisabled,
		"host": map[string]interface{}{
			"hostname": sys.Hostname,
			"cpu":      sys.CPU,
			"memory":   processMemory(),
		},
	})
}

func (d *DNSLeaf) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	d.statsMu.Lock()
	stats := d.stats
	d.statsMu.Unlock()
	d.blockMu.RLock()
	blocked := d.blockedCountLocked()
	d.blockMu.RUnlock()
	d.cacheMu.RLock()
	cacheEntries := len(d.cache)
	d.cacheMu.RUnlock()
	d.clientsMu.Lock()
	clients := len(d.clients)
	d.clientsMu.Unlock()
	d.readyMu.RLock()
	dnsReady := d.dnsReady
	httpReady := d.httpReady
	d.readyMu.RUnlock()
	activeUpstreams := len(d.activeUpstreams())
	persistenceOK := 1
	if d.persistenceError() != "" {
		persistenceOK = 0
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, "# HELP dnsleaf_queries_total Total DNS queries processed.\n# TYPE dnsleaf_queries_total counter\ndnsleaf_queries_total %d\n", stats.Queries)
	fmt.Fprintf(w, "# HELP dnsleaf_blocked_total Total blocked queries.\n# TYPE dnsleaf_blocked_total counter\ndnsleaf_blocked_total %d\n", stats.Blocked)
	fmt.Fprintf(w, "# HELP dnsleaf_local_total Total locally answered queries.\n# TYPE dnsleaf_local_total counter\ndnsleaf_local_total %d\n", stats.Local)
	fmt.Fprintf(w, "# HELP dnsleaf_cached_total Total cache hits.\n# TYPE dnsleaf_cached_total counter\ndnsleaf_cached_total %d\n", stats.Cached)
	fmt.Fprintf(w, "# HELP dnsleaf_forwarded_total Total forwarded queries.\n# TYPE dnsleaf_forwarded_total counter\ndnsleaf_forwarded_total %d\n", stats.Forwarded)
	fmt.Fprintf(w, "# HELP dnsleaf_blocked_domains Number of active blocked domains and rules.\n# TYPE dnsleaf_blocked_domains gauge\ndnsleaf_blocked_domains %d\n", blocked)
	fmt.Fprintf(w, "# HELP dnsleaf_cache_entries Number of cached DNS responses.\n# TYPE dnsleaf_cache_entries gauge\ndnsleaf_cache_entries %d\n", cacheEntries)
	fmt.Fprintf(w, "# HELP dnsleaf_clients Number of tracked clients.\n# TYPE dnsleaf_clients gauge\ndnsleaf_clients %d\n", clients)
	fmt.Fprintf(w, "# HELP dnsleaf_active_upstreams Number of active upstream endpoints.\n# TYPE dnsleaf_active_upstreams gauge\ndnsleaf_active_upstreams %d\n", activeUpstreams)
	fmt.Fprintf(w, "# HELP dnsleaf_dns_listeners_ready Number of DNS listeners whose serving loops started.\n# TYPE dnsleaf_dns_listeners_ready gauge\ndnsleaf_dns_listeners_ready %d\n", dnsReady)
	fmt.Fprintf(w, "# HELP dnsleaf_http_listeners_ready Number of HTTP listeners bound for serving.\n# TYPE dnsleaf_http_listeners_ready gauge\ndnsleaf_http_listeners_ready %d\n", httpReady)
	fmt.Fprintf(w, "# HELP dnsleaf_persistence_ok Whether runtime state persistence is healthy.\n# TYPE dnsleaf_persistence_ok gauge\ndnsleaf_persistence_ok %d\n", persistenceOK)
}

const maxBackupBytes = 256 * 1024 * 1024

func (d *DNSLeaf) backupArchive() ([]byte, error) {
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	var total int64
	addFile := func(name, path string, required bool) error {
		info, err := os.Stat(path)
		if err != nil {
			if !required && os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("backup source is not a regular file: %s", path)
		}
		if info.Size() < 0 || total+info.Size() > maxBackupBytes {
			return fmt.Errorf("backup exceeds %d MiB", maxBackupBytes/(1024*1024))
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetModTime(info.ModTime())
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}
		written, err := io.Copy(writer, file)
		if err != nil {
			return err
		}
		if written != info.Size() {
			return fmt.Errorf("backup source changed while reading: %s", path)
		}
		total += written
		return nil
	}
	if err := addFile("config.json", d.cfgPath, true); err != nil {
		_ = archive.Close()
		return nil, err
	}
	if err := addFile("stats.json", d.statePath, false); err != nil {
		_ = archive.Close()
		return nil, err
	}
	if err := filepath.Walk(d.gravityDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(d.gravityDir, path)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			return fmt.Errorf("invalid gravity backup path")
		}
		return addFile(filepath.ToSlash(filepath.Join("gravity", rel)), path, true)
	}); err != nil {
		_ = archive.Close()
		return nil, err
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (d *DNSLeaf) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := d.backupArchive()
	if err != nil {
		http.Error(w, "could not create backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="dnsleaf-backup.zip"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (d *DNSLeaf) activeUpstreams() []string {
	addrs := make([]string, 0, len(d.cfg.Upstreams)+len(d.cfg.UpstreamEndpoints))
	for _, addr := range d.cfg.Upstreams {
		if !d.disabledUpstream(addr) {
			addrs = append(addrs, addr)
		}
	}
	for _, endpoint := range d.cfg.UpstreamEndpoints {
		if !d.disabledUpstream(endpoint.URL) {
			addrs = append(addrs, endpoint.URL)
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
