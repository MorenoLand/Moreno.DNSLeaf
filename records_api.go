package main

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func (d *DNSLeaf) handleRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		writeJSON(w, d.cfg.Records)
	case "POST":
		var rec Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rec.Host = strings.ToLower(strings.TrimSuffix(rec.Host, "."))
		rec.IP = strings.TrimSpace(rec.IP)
		rec.Value = strings.TrimSpace(rec.Value)
		rec.Note = strings.TrimSpace(rec.Note)
		rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
		if rec.Type == "" {
			rec.Type = "A"
		}
		if rec.Value == "" {
			rec.Value = rec.IP
		}
		if rec.IP == "" {
			rec.IP = rec.Value
		}
		if rec.Host == "" || rec.Value == "" {
			http.Error(w, "host and value required", 400)
			return
		}
		d.cfg.Records = append(d.cfg.Records, rec)
		writeJSON(w, rec)
	case "PUT":
		var body struct {
			OldHost string `json:"old_host"`
			OldIP   string `json:"old_ip"`
			Host    string `json:"host"`
			IP      string `json:"ip"`
			Type    string `json:"type"`
			Value   string `json:"value"`
			Note    string `json:"note"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(body.Host), "."))
		ip := strings.TrimSpace(body.IP)
		value := strings.TrimSpace(body.Value)
		if value == "" {
			value = ip
		}
		recType := strings.ToUpper(strings.TrimSpace(body.Type))
		if recType == "" {
			recType = "A"
		}
		if host == "" || value == "" {
			http.Error(w, "host and value required", 400)
			return
		}
		for i, rec := range d.cfg.Records {
			if rec.IP == body.OldIP && strings.EqualFold(rec.Host, body.OldHost) {
				d.cfg.Records[i] = Record{Host: host, Type: recType, Value: value, IP: value, Note: strings.TrimSpace(body.Note)}
				writeJSON(w, d.cfg.Records[i])
				return
			}
		}
		http.Error(w, "record not found", 404)
	case "DELETE":
		var rec Record
		if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		for i, r := range d.cfg.Records {
			if r.IP == rec.IP && strings.EqualFold(r.Host, rec.Host) {
				d.cfg.Records = append(d.cfg.Records[:i], d.cfg.Records[i+1:]...)
				break
			}
		}
		w.WriteHeader(204)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func recordFromRR(rr dns.RR) (Record, bool) {
	host := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
	rec := Record{}
	note := ""
	if idx := strings.Index(rr.String(), ";"); idx >= 0 {
		note = strings.TrimSpace(rr.String()[idx+1:])
	}
	switch v := rr.(type) {
	case *dns.A:
		rec = Record{Host: host, Type: "A", Value: v.A.String(), IP: v.A.String(), Note: note}
	case *dns.AAAA:
		rec = Record{Host: host, Type: "AAAA", Value: v.AAAA.String(), IP: v.AAAA.String(), Note: note}
	case *dns.CNAME:
		rec = Record{Host: host, Type: "CNAME", Value: strings.TrimSuffix(v.Target, "."), Note: note}
	case *dns.TXT:
		rec = Record{Host: host, Type: "TXT", Value: strings.Join(v.Txt, ""), Note: note}
	case *dns.MX:
		rec = Record{Host: host, Type: "MX", Value: strings.TrimSuffix(v.Mx, "."), Priority: v.Preference, Note: note}
	case *dns.SRV:
		rec = Record{Host: host, Type: "SRV", Value: strings.TrimSuffix(v.Target, "."), Priority: v.Priority, Weight: v.Weight, Port: v.Port, Note: note}
	case *dns.PTR:
		rec = Record{Host: host, Type: "PTR", Value: strings.TrimSuffix(v.Ptr, "."), Note: note}
	default:
		return Record{}, false
	}
	return rec, true
}

func (d *DNSLeaf) handleImportRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(64 * 1024 * 1024); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer file.Close()
		overwrite := strings.EqualFold(r.FormValue("overwrite"), "true") || r.FormValue("overwrite") == "1"
		imported, skipped, err := d.importRecordsFromReader(file, r.FormValue("zone"), header.Filename, overwrite)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]int{"imported": imported, "skipped": skipped})
		return
	}
	var body struct {
		Path      string `json:"path"`
		Zone      string `json:"zone"`
		Overwrite bool   `json:"overwrite"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	path := strings.TrimSpace(body.Path)
	if path == "" {
		http.Error(w, "path required", 400)
		return
	}
	path = d.runtimePath(path)
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer f.Close()
	imported, skipped, err := d.importRecordsFromReader(f, body.Zone, path, body.Overwrite)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]int{"imported": imported, "skipped": skipped})
}

func (d *DNSLeaf) importRecordsFromReader(r io.Reader, zone, origin string, overwrite bool) (int, int, error) {
	zp := dns.NewZoneParser(r, dns.Fqdn(zone), origin)
	imported := 0
	skipped := 0
	seen := make(map[string]bool)
	if !overwrite {
		for _, rec := range d.cfg.Records {
			seen[strings.ToLower(rec.Host)+"|"+strings.ToUpper(rec.Type)+"|"+rec.Value] = true
		}
	}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rec, supported := recordFromRR(rr)
		if !supported {
			skipped++
			continue
		}
		key := strings.ToLower(rec.Host) + "|" + strings.ToUpper(rec.Type) + "|" + rec.Value
		if !overwrite && seen[key] {
			skipped++
			continue
		}
		d.cfg.Records = append(d.cfg.Records, rec)
		seen[key] = true
		imported++
	}
	if err := zp.Err(); err != nil {
		return 0, 0, err
	}
	return imported, skipped, nil
}
