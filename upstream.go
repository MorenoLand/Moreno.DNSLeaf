package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	mathrand "math/rand"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

func stripClientSubnet(msg *dns.Msg) *dns.Msg {
	if msg == nil || msg.IsEdns0() == nil {
		return msg
	}
	copyMsg := msg.Copy()
	opt := copyMsg.IsEdns0()
	options := make([]dns.EDNS0, 0, len(opt.Option))
	for _, option := range opt.Option {
		if _, ok := option.(*dns.EDNS0_SUBNET); !ok {
			options = append(options, option)
		}
	}
	opt.Option = options
	return copyMsg
}

func validUpstreamResponse(query, response *dns.Msg) bool {
	if query == nil || response == nil || response.Id != query.Id || len(query.Question) != 1 || len(response.Question) != 1 {
		return false
	}
	want := query.Question[0]
	got := response.Question[0]
	return strings.EqualFold(want.Name, got.Name) && want.Qtype == got.Qtype && want.Qclass == got.Qclass
}

func exchangeUpstreamEndpoint(endpoint UpstreamEndpoint, query *dns.Msg) (*dns.Msg, error) {
	route, err := parseUpstreamEndpoint(endpoint)
	if err != nil {
		return nil, err
	}
	switch route.scheme {
	case "udp", "tcp", "tls":
		client := &dns.Client{Net: route.scheme, Timeout: 3 * time.Second}
		if route.scheme == "tls" {
			client.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: route.serverName}
		}
		response, _, err := client.Exchange(query, route.address)
		return response, err
	case "https":
		wire, err := query.Pack()
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(http.MethodPost, route.url, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		transport := proxyTransport.Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: route.serverName}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return nil, fmt.Errorf("upstream HTTP status %d", response.StatusCode)
		}
		if contentType := response.Header.Get("Content-Type"); contentType != "" {
			parsed, _, parseErr := mime.ParseMediaType(contentType)
			if parseErr != nil || parsed != "application/dns-message" {
				return nil, fmt.Errorf("upstream content type %q", contentType)
			}
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
		if err != nil {
			return nil, err
		}
		if len(data) > 64*1024 {
			return nil, fmt.Errorf("upstream DNS message exceeds 64 KiB")
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			return nil, err
		}
		return msg, nil
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", route.scheme)
	}
}

func (d *DNSLeaf) forward(r *dns.Msg) *dns.Msg {
	udpClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	tcpClient := &dns.Client{Net: "tcp", Timeout: 3 * time.Second}
	query := r
	if d.cfg.StripECS {
		query = stripClientSubnet(r)
	}
	configured := d.upstreamsForQuery(r)
	type target struct {
		address  string
		endpoint *UpstreamEndpoint
	}
	targets := make([]target, 0, len(configured)+len(d.cfg.UpstreamEndpoints))
	for _, addr := range configured {
		if !d.disabledUpstream(addr) {
			targets = append(targets, target{address: addr})
		}
	}
	for _, configuredEndpoint := range d.cfg.UpstreamEndpoints {
		endpoint := configuredEndpoint
		if !d.disabledUpstream(endpoint.URL) {
			targets = append(targets, target{endpoint: &endpoint})
		}
	}
	mathrand.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	for _, item := range targets {
		var resp *dns.Msg
		var err error
		if item.endpoint != nil {
			resp, err = exchangeUpstreamEndpoint(*item.endpoint, query)
			if err == nil {
				route, routeErr := parseUpstreamEndpoint(*item.endpoint)
				if routeErr == nil && route.scheme == "udp" && resp != nil && resp.Truncated {
					fallback := *item.endpoint
					fallback.URL = "tcp://" + route.address
					resp, err = exchangeUpstreamEndpoint(fallback, query)
				}
			}
		} else {
			resp, _, err = udpClient.Exchange(query, item.address)
			if err == nil && resp != nil && resp.Truncated {
				resp, _, err = tcpClient.Exchange(query, item.address)
			}
		}
		if err != nil || !validUpstreamResponse(query, resp) {
			continue
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
