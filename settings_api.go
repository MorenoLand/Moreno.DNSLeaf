package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

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
