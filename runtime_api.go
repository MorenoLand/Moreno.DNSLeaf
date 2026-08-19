package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

func (d *DNSLeaf) handleAudit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		d.auditMu.Lock()
		items := append([]AuditEntry(nil), d.audit...)
		d.auditMu.Unlock()
		writeJSON(w, items)
	case http.MethodDelete:
		d.auditMu.Lock()
		d.audit = d.audit[:0]
		d.auditMu.Unlock()
		d.requestPersistentSave()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
	if _, exists := d.loginAttempts[client]; !exists && len(d.loginAttempts) >= maxLoginEntries {
		for key, attempt := range d.loginAttempts {
			if attempt.FirstFailed.IsZero() || now.Sub(attempt.FirstFailed) >= loginWindow {
				delete(d.loginAttempts, key)
				if len(d.loginAttempts) < maxLoginEntries {
					break
				}
			}
		}
		if len(d.loginAttempts) >= maxLoginEntries {
			for key := range d.loginAttempts {
				delete(d.loginAttempts, key)
				break
			}
		}
	}
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
		now := time.Now()
		for existing, session := range d.sessions {
			if now.After(session.Expires) {
				delete(d.sessions, existing)
			}
		}
		if len(d.sessions) >= maxSessions {
			oldestToken := ""
			var oldest time.Time
			for existing, session := range d.sessions {
				if oldestToken == "" || session.Expires.Before(oldest) {
					oldestToken = existing
					oldest = session.Expires
				}
			}
			if oldestToken != "" {
				delete(d.sessions, oldestToken)
			}
		}
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
