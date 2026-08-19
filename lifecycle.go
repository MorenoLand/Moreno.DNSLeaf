package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

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
