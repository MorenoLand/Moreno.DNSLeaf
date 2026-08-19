package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func (d *DNSLeaf) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		items := make([]map[string]interface{}, 0, len(d.cfg.Upstreams)+len(d.cfg.UpstreamEndpoints))
		for _, addr := range d.cfg.Upstreams {
			items = append(items, map[string]interface{}{"address": addr, "protocol": "udp", "enabled": !d.disabledUpstream(addr)})
		}
		for _, endpoint := range d.cfg.UpstreamEndpoints {
			route, _ := parseUpstreamEndpoint(endpoint)
			items = append(items, map[string]interface{}{"address": endpoint.URL, "protocol": route.scheme, "server_name": endpoint.ServerName, "enabled": !d.disabledUpstream(endpoint.URL)})
		}
		writeJSON(w, items)
	case "POST":
		var body struct {
			Address    string `json:"address"`
			Protocol   string `json:"protocol"`
			ServerName string `json:"server_name"`
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
		protocol := strings.ToLower(strings.TrimSpace(body.Protocol))
		if protocol == "" || protocol == "udp" || protocol == "tcp" {
			if protocol == "" || protocol == "udp" {
				if !strings.Contains(addr, ":") {
					addr = addr + ":53"
				}
				d.cfg.Upstreams = append(d.cfg.Upstreams, addr)
				writeJSON(w, map[string]string{"address": addr, "protocol": "udp"})
				return
			}
			if !strings.Contains(addr, "://") {
				addr = protocol + "://" + addr
			}
		} else if !strings.Contains(addr, "://") {
			addr = protocol + "://" + addr
		}
		endpoint := UpstreamEndpoint{URL: addr, ServerName: strings.TrimSpace(body.ServerName)}
		if err := validateUpstreamEndpoint(endpoint); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		d.cfg.UpstreamEndpoints = append(d.cfg.UpstreamEndpoints, endpoint)
		writeJSON(w, map[string]string{"address": endpoint.URL, "protocol": protocol})
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
		nextEndpoints := d.cfg.UpstreamEndpoints[:0]
		for _, endpoint := range d.cfg.UpstreamEndpoints {
			if endpoint.URL != body.Address {
				nextEndpoints = append(nextEndpoints, endpoint)
			}
		}
		d.cfg.UpstreamEndpoints = nextEndpoints
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
