package main

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

func (d *DNSLeaf) serveHTTPProxy(addr string) error {
	srv := newHTTPServer(addr, http.HandlerFunc(d.handleHTTPProxy), log.New(serverLogWriter{dad: d}, "", 0))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	d.registerHTTPServer(srv, listener)
	d.consoleLogf("[DNSLeaf] HTTP proxy listening on %s", addr)
	if err := srv.Serve(listener); err != nil && !d.isStopping() && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
