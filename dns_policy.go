package main

import (
	"fmt"
	mathrand "math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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
			if (qtype == dns.TypeHTTPS && recType == "HTTPS") || (qtype == dns.TypeSVCB && recType == "SVCB") {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 300 IN %s %s", dns.Fqdn(qname), recType, value)); err == nil {
					results = append(results, rr)
				}
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

func anonymizeClientIP(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		copyIP := append(net.IP(nil), v4...)
		copyIP[3] = 0
		return copyIP.String()
	}
	copyIP := append(net.IP(nil), ip.To16()...)
	for i := 8; i < len(copyIP); i++ {
		copyIP[i] = 0
	}
	return copyIP.String()
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

func (d *DNSLeaf) evictOldestClientLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, client := range d.clients {
		if client == nil {
			delete(d.clients, key)
			return
		}
		if oldestKey == "" || client.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = client.lastSeen
		}
	}
	if oldestKey != "" {
		delete(d.clients, oldestKey)
	}
}

func (d *DNSLeaf) trackClient(ip, action string) {
	if strings.TrimSpace(ip) == "" {
		return
	}
	d.clientsMu.Lock()
	defer d.clientsMu.Unlock()
	c := d.clients[ip]
	if c == nil {
		if len(d.clients) >= maxTrackedClients {
			d.evictOldestClientLocked()
		}
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

func capTimeHitMap(entries map[string][]time.Time, cutoff time.Time, max int) {
	if len(entries) < max {
		return
	}
	for key, hits := range entries {
		if len(hits) == 0 || hits[len(hits)-1].Before(cutoff) {
			delete(entries, key)
			if len(entries) < max {
				return
			}
		}
	}
	if len(entries) >= max {
		for key := range entries {
			delete(entries, key)
			break
		}
	}
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
	if hits == nil {
		capTimeHitMap(d.rateHits, cutoff, maxRateEntries)
	}
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
	if hits == nil {
		capTimeHitMap(d.anomalyHits, cutoff, maxAnomalyEntries)
	}
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
