package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
	"unicode"
)

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
		if r.URL.Path == "/" || r.URL.Path == "/dnsleaf.png" || r.URL.Path == "/dns-query" || r.URL.Path == "/api/ping" || r.URL.Path == "/api/healthz" || r.URL.Path == "/api/readyz" || r.URL.Path == "/api/login" || r.URL.Path == "/api/session" {
			next.ServeHTTP(w, r)
			return
		}
		s, ok := d.sessionFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if (r.URL.Path == "/api/users" || r.URL.Path == "/api/audit" || r.URL.Path == "/api/backup") && s.Role != "admin" {
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
			d.addAudit(r, status)
		}
		buffered.flush(w)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}
