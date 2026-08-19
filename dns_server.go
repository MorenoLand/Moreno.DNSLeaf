package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

	if d.cfg.ResolverDisabled {
		resp := d.forward(r)
		resp.Compress = true
		dur := time.Since(start)
		d.addStat("forwarded")
		d.trackClient(clientIP, "forwarded")
		d.addLog(client, localAddr, transport, qname, qtypeStr, "forwarded", dnsAnswers(resp), dur)
		return resp
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
