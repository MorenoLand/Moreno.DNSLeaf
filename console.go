package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/gdamore/tcell/v3"
	"github.com/x0rbyte/tview"
)

func newConsoleUI(dad *DNSLeaf) (*consoleUI, error) {
	screen, err := tcell.NewScreen()
	if err != nil {
		return nil, err
	}
	if err := screen.Init(); err != nil {
		return nil, err
	}

	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)

	sidebar := tview.NewTextView().
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(true).
		SetTextStyle(textStyle)
	sidebar.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetBorderPadding(0, 0, 1, 1).
		SetTitle(" DNSLeaf ").
		SetTitleStyle(titleStyle)

	logView := tview.NewTextView().
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(false).
		SetTextStyle(textStyle)
	logView.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetTitle(" Console ").
		SetTitleStyle(titleStyle)

	input := tview.NewInputField().
		SetLabel("> ").
		SetLabelStyle(textStyle).
		SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).
		SetPlaceholder("Type a command...").
		SetPlaceholderStyle(tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen))
	input.Box.
		SetBorders(tview.BordersAll).
		SetBorderSet(tview.BorderSetRound()).
		SetBorderStyle(borderStyle).
		SetBorderPadding(0, 0, 1, 1)

	ui := &consoleUI{
		screen:   screen,
		sidebar:  sidebar,
		log:      logView,
		input:    input,
		logStyle: textStyle,
		dad:      dad,
		lines:    []string{"dnsleaf ready. Type 'help'."},
	}

	input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		command := strings.TrimSpace(ui.input.GetText())
		ui.input.SetText("")
		if command == "" {
			ui.wake()
			return
		}
		ui.runCommand(command)
	})

	body := tview.NewFlex().
		AddItem(sidebar, consoleSidebarWidth, 0, false).
		AddItem(logView, 0, 1, false)

	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, false).
		AddItem(input, consoleInputHeight, 0, true)

	ui.app = tview.NewApplication()
	ui.app.SetScreen(screen)
	ui.app.SetRoot(root)
	ui.refreshSidebar()
	ui.refreshLog()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if dad.ui != ui {
				return
			}
			ui.app.QueueUpdateDraw(func() {
				ui.refreshSidebar()
			})
		}
	}()

	return ui, nil
}

func dnsleafPingURL(cfg Config) string {
	base := webURL(cfg.HTTP)
	return strings.TrimRight(base, "/") + "/api/ping"
}

func runningDNSLeaf(cfg Config) bool {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(dnsleafPingURL(cfg))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		App string `json:"app"`
		OK  bool   `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body); err != nil {
		return false
	}
	return resp.StatusCode == http.StatusOK && body.App == "dnsleaf" && body.OK
}

func runRemoteConsole(cfg Config) error {
	return runRemoteConsoleBase(webURL(cfg.HTTP))
}

func runRemoteConsoleBase(base string) error {
	jar, _ := cookiejar.New(nil)
	base = normalizeRemoteBase(base)
	rc := &remoteConsole{
		base:   strings.TrimRight(base, "/"),
		client: &http.Client{Timeout: 10 * time.Second, Jar: jar},
		lines:  []string{"connected to running DNSLeaf at " + base, "type 'login <user> <pass>', 'status', 'reload', 'blocklists', 'upstreams', or 'quit'."},
	}
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)
	rc.sidebar = tview.NewTextView().SetScrollable(true).SetWrap(true).SetWordWrap(true).SetTextStyle(textStyle)
	rc.sidebar.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(0, 0, 1, 1).SetTitle(" DNSLeaf ").SetTitleStyle(titleStyle)
	rc.log = tview.NewTextView().SetScrollable(true).SetWrap(true).SetWordWrap(false).SetTextStyle(textStyle)
	rc.log.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetTitle(" DNSLeaf Remote ").SetTitleStyle(titleStyle)
	rc.input = tview.NewInputField().SetLabel("> ").SetLabelStyle(textStyle).SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).SetPlaceholder("Type a remote command...").SetPlaceholderStyle(tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen))
	rc.input.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(0, 0, 1, 1)
	rc.input.SetDoneFunc(func(key tcell.Key) {
		if key != tcell.KeyEnter {
			return
		}
		cmd := strings.TrimSpace(rc.input.GetText())
		rc.input.SetText("")
		if cmd != "" {
			rc.run(cmd)
		}
	})
	body := tview.NewFlex().AddItem(rc.sidebar, consoleSidebarWidth, 0, false).AddItem(rc.log, 0, 1, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(body, 0, 1, false).AddItem(rc.input, consoleInputHeight, 0, true)
	rc.app = tview.NewApplication()
	rc.app.SetRoot(root)
	rc.refreshSidebar()
	rc.refresh()
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if rc.app == nil {
				return
			}
			rc.app.QueueUpdateDraw(func() {
				rc.refreshSidebar()
			})
		}
	}()
	return rc.app.Run()
}

func normalizeRemoteBase(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return "http://127.0.0.1:8080"
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}
	return strings.TrimRight(server, "/")
}

func promptRemoteServer(defaultServer string) (string, error) {
	var chosen string
	app := tview.NewApplication()
	titleStyle := tcell.StyleDefault.Foreground(tcell.ColorLightGreen).Bold(true)
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkSeaGreen)
	textStyle := tcell.StyleDefault.Foreground(tcell.ColorHoneydew)
	input := tview.NewInputField().
		SetLabel("Server: ").
		SetText(defaultServer).
		SetLabelStyle(textStyle).
		SetFieldStyle(tcell.StyleDefault.Foreground(tcell.ColorPaleGreen)).
		SetPlaceholder("http://host:8080")
	input.Box.SetBorders(tview.BordersAll).SetBorderSet(tview.BorderSetRound()).SetBorderStyle(borderStyle).SetBorderPadding(1, 1, 2, 2).SetTitle(" DNSLeaf Remote ").SetTitleStyle(titleStyle)
	input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			app.Stop()
			return
		}
		if key == tcell.KeyEnter {
			chosen = strings.TrimSpace(input.GetText())
			app.Stop()
		}
	})
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().AddItem(nil, 0, 1, false).AddItem(input, 72, 0, true).AddItem(nil, 0, 1, false), 5, 0, true).
		AddItem(nil, 0, 1, false)
	app.SetRoot(root)
	if err := app.Run(); err != nil {
		return "", err
	}
	if chosen == "" {
		return "", fmt.Errorf("remote server not selected")
	}
	return normalizeRemoteBase(chosen), nil
}

func (rc *remoteConsole) append(line string) {
	rc.mu.Lock()
	rc.lines = append(rc.lines, line)
	if len(rc.lines) > 1000 {
		rc.lines = rc.lines[len(rc.lines)-1000:]
	}
	rc.mu.Unlock()
	rc.refresh()
}

func (rc *remoteConsole) refresh() {
	rc.mu.Lock()
	text := strings.Join(rc.lines, "\n")
	rc.mu.Unlock()
	rc.log.SetText(text)
	rc.log.ScrollToEnd()
}

func (rc *remoteConsole) refreshSidebar() {
	var out map[string]interface{}
	if err := rc.api("GET", "/api/status", nil, &out); err != nil {
		rc.sidebar.SetText(strings.Join([]string{
			"remote",
			"  " + rc.base,
			"  login required or offline",
			"",
			"commands",
			"  login <user> <pass>",
			"  status",
			"  reload",
			"  blocklists",
			"  upstreams",
			"  quit",
		}, "\n"))
		return
	}
	host := mapString(out, "host")
	stats := mapString(out, "stats")
	lines := []string{
		"remote",
		"  " + rc.base,
		"",
		"status",
		fmt.Sprintf("  uptime: %v", out["uptime"]),
		fmt.Sprintf("  memory: %v", host["memory"]),
		fmt.Sprintf("  cpu:    %v", host["cpu"]),
		fmt.Sprintf("  listen: %v", out["listen"]),
		fmt.Sprintf("  web:    %v", out["http"]),
		"",
		"queries",
		fmt.Sprintf("  total:     %v", stats["total_queries"]),
		fmt.Sprintf("  blocked:   %v", stats["blocked"]),
		fmt.Sprintf("  local:     %v", stats["local"]),
		fmt.Sprintf("  cached:    %v", stats["cached"]),
		fmt.Sprintf("  forwarded: %v", stats["forwarded"]),
		"",
		"config",
		fmt.Sprintf("  records:   %v", out["records_count"]),
		fmt.Sprintf("  blocked:   %v", out["blocked_count"]),
		fmt.Sprintf("  upstreams: %v/%v", out["active_upstreams"], out["upstream_count"]),
		fmt.Sprintf("  clients:   %v", out["client_count"]),
		"",
		"main navigation",
		"  dashboard",
		"  query log",
		"  clients",
		"",
		"dns control",
		"  local dns",
		"  blocklists",
		"  profiles",
		"  upstreams",
		"",
		"system",
		"  settings",
		"  certificates",
		"  server log",
		"  users",
	}
	rc.sidebar.SetText(strings.Join(lines, "\n"))
}

func mapString(v map[string]interface{}, key string) map[string]interface{} {
	if m, ok := v[key].(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{}
}

func (rc *remoteConsole) run(command string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	if strings.EqualFold(fields[0], "login") {
		if len(fields) >= 2 {
			rc.append("> login " + fields[1] + " ******")
		} else {
			rc.append("> login")
		}
	} else {
		rc.append("> " + command)
	}
	switch strings.ToLower(fields[0]) {
	case "quit", "exit":
		rc.app.Stop()
	case "clear":
		rc.mu.Lock()
		rc.lines = nil
		rc.mu.Unlock()
		rc.refresh()
	case "login":
		if len(fields) < 3 {
			rc.append("usage: login <username> <password>")
			return
		}
		var out map[string]interface{}
		if err := rc.api("POST", "/api/login", map[string]string{"username": fields[1], "password": fields[2]}, &out); err != nil {
			rc.append("login failed: " + err.Error())
			return
		}
		rc.append("logged in")
	case "status":
		var out map[string]interface{}
		if err := rc.api("GET", "/api/status", nil, &out); err != nil {
			rc.append("status failed: " + err.Error())
			return
		}
		rc.append(fmt.Sprintf("uptime=%v blocked=%v queries=%v clients=%v", out["uptime"], out["blocked_count"], out["stats"], out["client_count"]))
	case "reload":
		var out map[string]interface{}
		if err := rc.api("POST", "/api/reload", map[string]string{}, &out); err != nil {
			rc.append("reload failed: " + err.Error())
			return
		}
		rc.append(fmt.Sprintf("gravity updated, blocked=%v", out["blocked_count"]))
	case "blocklists":
		var lists []BlocklistSource
		if err := rc.api("GET", "/api/blocklists", nil, &lists); err != nil {
			rc.append("blocklists failed: " + err.Error())
			return
		}
		for _, l := range lists {
			state := "disabled"
			if l.Enabled {
				state = "enabled"
			}
			rc.append(fmt.Sprintf("%s  %s  loaded=%d  %s", l.Source, state, l.LastLoaded, l.LastError))
		}
	case "upstreams":
		var ups []map[string]interface{}
		if err := rc.api("GET", "/api/upstreams", nil, &ups); err != nil {
			rc.append("upstreams failed: " + err.Error())
			return
		}
		for _, up := range ups {
			rc.append(fmt.Sprintf("%v enabled=%v", up["address"], up["enabled"]))
		}
	default:
		rc.append("unknown remote command")
	}
}

func (rc *remoteConsole) api(method, path string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, rc.base+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-DNSLeaf-Request", "1")
	resp, err := rc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (ui *consoleUI) wake() {}

func (ui *consoleUI) refreshSidebar() {
	d := ui.dad
	d.cfgMu.RLock()
	defer d.cfgMu.RUnlock()
	d.statsMu.Lock()
	s := d.stats
	d.statsMu.Unlock()
	d.blockMu.RLock()
	blockedCount := d.blockedCountLocked()
	d.blockMu.RUnlock()
	clients := d.clientList()
	active := len(d.activeUpstreams())
	policy := "open"
	if d.cfg.WhitelistOnly {
		policy = "whitelist"
	} else if d.cfg.LANOnly {
		policy = "LAN only"
	}
	lines := []string{
		"status",
		fmt.Sprintf("  uptime: %s", time.Since(d.started).Truncate(time.Second)),
		fmt.Sprintf("  memory: %s", processMemory()),
		fmt.Sprintf("  listen: %s", d.cfg.Listen),
		fmt.Sprintf("  web:    %s", d.cfg.HTTP),
		fmt.Sprintf("  policy: %s", policy),
		"",
		"queries",
		fmt.Sprintf("  total:     %d", s.Queries),
		fmt.Sprintf("  blocked:   %d", s.Blocked),
		fmt.Sprintf("  local:     %d", s.Local),
		fmt.Sprintf("  cached:    %d", s.Cached),
		fmt.Sprintf("  forwarded: %d", s.Forwarded),
		"",
		"config",
		fmt.Sprintf("  records:   %d", len(d.cfg.Records)),
		fmt.Sprintf("  blocked:   %d", blockedCount),
		fmt.Sprintf("  upstreams: %d/%d", active, len(d.cfg.Upstreams)),
		fmt.Sprintf("  clients:   %d", len(clients)),
	}
	ui.sidebar.SetText(strings.Join(lines, "\n"))
}

func (ui *consoleUI) refreshLog() {
	ui.mu.Lock()
	lines := append([]string(nil), ui.lines...)
	ui.mu.Unlock()
	ui.log.SetText(strings.Join(lines, "\n"))
	ui.log.ScrollToEnd()
}

func (ui *consoleUI) appendLog(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	ui.mu.Lock()
	ui.lines = append(ui.lines, line)
	if len(ui.lines) > 1000 {
		ui.lines = ui.lines[len(ui.lines)-1000:]
	}
	running := ui.running
	inCommand := ui.inCommand
	ui.mu.Unlock()
	if ui.app != nil && running && !inCommand {
		ui.app.QueueUpdateDraw(func() {
			ui.refreshLog()
		})
		return
	}
	ui.refreshLog()
}

func (ui *consoleUI) runCommand(command string) {
	ui.mu.Lock()
	ui.inCommand = true
	ui.mu.Unlock()
	defer func() {
		ui.mu.Lock()
		ui.inCommand = false
		ui.mu.Unlock()
	}()
	ui.appendLog("> " + command)
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return
	}
	d := ui.dad
	d.cfgMu.Lock()
	defer func() {
		d.cfgMu.Unlock()
		ui.refreshSidebar()
	}()
	switch strings.ToLower(fields[0]) {
	case "help":
		ui.appendLog(strings.Join([]string{
			"help                         show commands",
			"clear                        clear console",
			"status                       print server status",
			"clients                      list known clients",
			"blocklists                   list subscribed blocklists",
			"blocklist add <name> <src>   add local path or URL",
			"blocklist enable <src>       enable subscribed list",
			"blocklist disable <src>      disable subscribed list",
			"blocklist remove <src>       remove subscribed list",
			"gravity [list]               refresh all or one blocklist",
			"reload                       reload all blocklists",
			"users                        list panel users",
			"user add <u> <p> [role]      add panel user",
			"user reset <u> <p>           reset password",
			"user role <u> <role>         set admin/viewer",
			"user remove <u>              remove panel user",
			"whitelist                    list allowed IPs/CIDRs",
			"whitelist add <ip|cidr>      allow client",
			"whitelist remove <ip|cidr>   remove allowed client",
			"upstreams                    list upstreams",
			"upstream add <addr>          add upstream",
			"upstream enable <addr>       enable upstream",
			"upstream disable <addr>      disable upstream",
			"upstream remove <addr>       remove upstream",
			"settings                     print key settings",
			"quit                         exit dnsleaf",
		}, "\n"))
	case "clear":
		ui.mu.Lock()
		ui.lines = nil
		ui.mu.Unlock()
		ui.refreshLog()
	case "status":
		d.statsMu.Lock()
		s := d.stats
		d.statsMu.Unlock()
		ui.appendLog(fmt.Sprintf("uptime=%s listen=%s web=%s queries=%d blocked=%d local=%d cached=%d forwarded=%d",
			time.Since(d.started).Truncate(time.Second), d.cfg.Listen, d.cfg.HTTP, s.Queries, s.Blocked, s.Local, s.Cached, s.Forwarded))
	case "clients":
		clients := d.clientList()
		if len(clients) == 0 {
			ui.appendLog("No clients yet.")
			return
		}
		for _, c := range clients {
			name := c.Name
			if name == "" {
				name = "-"
			}
			ui.appendLog(fmt.Sprintf("%s  name=%s allowed=%t lan=%t whitelist=%t queries=%d denied=%d last=%s", c.IP, name, c.Allowed, c.LAN, c.Whitelisted, c.Queries, c.Denied, c.LastSeen))
		}
	case "users":
		if len(d.cfg.Auth.Users) == 0 {
			ui.appendLog("No users configured.")
			return
		}
		for _, user := range d.cfg.Auth.Users {
			ui.appendLog(fmt.Sprintf("%s  role=%s created=%s", user.Username, user.Role, user.CreatedAt))
		}
	case "user":
		ui.runUserCommand(fields[1:])
	case "blocklists":
		ui.runBlocklistsCommand()
	case "blocklist":
		ui.runBlocklistCommand(fields[1:])
	case "reload":
		d.resetBlocked()
		d.initBlocked()
		if err := d.loadBlocklist(); err != nil {
			ui.appendLog(fmt.Sprintf("reload failed: %v", err))
		} else {
			ui.appendLog("blocklists reloaded")
		}
	case "gravity":
		target := ""
		if len(fields) > 1 {
			target = strings.Join(fields[1:], " ")
		}
		if err := d.refreshBlocklistTarget(target); err != nil {
			ui.appendLog(fmt.Sprintf("gravity failed: %v", err))
		} else if target == "" {
			if err := d.saveConfig(); err != nil {
				ui.appendLog(fmt.Sprintf("gravity save failed: %v", err))
				return
			}
			ui.appendLog("gravity updated")
		} else {
			if err := d.saveConfig(); err != nil {
				ui.appendLog(fmt.Sprintf("gravity save failed: %v", err))
				return
			}
			ui.appendLog("gravity updated " + target)
		}
	case "whitelist":
		ui.runWhitelistCommand(fields[1:])
	case "upstreams":
		ui.runUpstreamsCommand()
	case "upstream":
		ui.runUpstreamCommand(fields[1:])
	case "settings":
		ui.appendLog(fmt.Sprintf("listen=%s web=%s cache=%t cache_size=%d cache_ttl=%ds lan_only=%t whitelist_only=%t blocklist=%s",
			d.cfg.Listen, d.cfg.HTTP, d.cfg.Cache, d.cfg.CacheSize, d.cfg.CacheTTL, d.cfg.LANOnly, d.cfg.WhitelistOnly, d.cfg.Blocklist))
	case "quit", "exit":
		d.Stop()
		return
	default:
		ui.appendLog("Unknown command. Type 'help'.")
	}
}

func (ui *consoleUI) runUserCommand(args []string) {
	if len(args) == 0 {
		ui.appendLog("usage: user add|reset|role|remove ...")
		return
	}
	d := ui.dad
	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) < 3 {
			ui.appendLog("usage: user add <username> <password> [admin|viewer]")
			return
		}
		role := "viewer"
		if len(args) >= 4 {
			role = args[3]
		}
		if role != "admin" && role != "viewer" {
			ui.appendLog("role must be admin or viewer")
			return
		}
		if !validUsername(args[1]) || args[2] == "" || len(args[2]) > 4096 {
			ui.appendLog("username and password are invalid")
			return
		}
		if _, ok := d.findUser(args[1]); ok {
			ui.appendLog("user already exists")
			return
		}
		d.cfg.Auth.Enabled = true
		d.cfg.Auth.Users = append(d.cfg.Auth.Users, UserAuth{Username: args[1], PasswordHash: passwordHash(args[2]), Role: role, CreatedAt: time.Now().Format(time.RFC3339)})
		if err := d.saveConfig(); err != nil {
			ui.appendLog(fmt.Sprintf("save failed: %v", err))
			return
		}
		ui.appendLog(fmt.Sprintf("added user %s as %s", args[1], role))
	case "reset":
		if len(args) < 3 {
			ui.appendLog("usage: user reset <username> <password>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				d.cfg.Auth.Users[i].PasswordHash = passwordHash(args[2])
				if err := d.saveConfig(); err != nil {
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("reset password for %s", args[1]))
				return
			}
		}
		ui.appendLog("user not found")
	case "role":
		if len(args) < 3 || (args[2] != "admin" && args[2] != "viewer") {
			ui.appendLog("usage: user role <username> <admin|viewer>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				if user.Role == "admin" && args[2] != "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot demote the last administrator")
					return
				}
				d.cfg.Auth.Users[i].Role = args[2]
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users[i] = user
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("updated %s to %s", args[1], args[2]))
				return
			}
		}
		ui.appendLog("user not found")
	case "remove":
		if len(args) < 2 {
			ui.appendLog("usage: user remove <username>")
			return
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[1] {
				if len(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot remove the last user")
					return
				}
				if user.Role == "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					ui.appendLog("cannot remove the last administrator")
					return
				}
				users := append([]UserAuth(nil), d.cfg.Auth.Users...)
				d.cfg.Auth.Users = append(d.cfg.Auth.Users[:i], d.cfg.Auth.Users[i+1:]...)
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users = users
					ui.appendLog(fmt.Sprintf("save failed: %v", err))
					return
				}
				d.revokeUserSessions(user.Username)
				ui.appendLog(fmt.Sprintf("removed %s", args[1]))
				return
			}
		}
		ui.appendLog("user not found")
	default:
		ui.appendLog("usage: user add|reset|role|remove ...")
	}
}

func (ui *consoleUI) runBlocklistsCommand() {
	d := ui.dad
	if len(d.cfg.Blocklists) == 0 {
		ui.appendLog("No blocklists configured.")
		return
	}
	for i, list := range d.cfg.Blocklists {
		state := "enabled"
		if !list.Enabled {
			state = "disabled"
		}
		errText := ""
		if list.LastError != "" {
			errText = " error=" + list.LastError
		}
		ui.appendLog(fmt.Sprintf("%d  %s  %s  source=%s loaded=%d refreshed=%s exceptions=%d%s", i+1, list.Name, state, list.Source, list.LastLoaded, list.LastRefreshed, len(list.Allowlist), errText))
	}
}

func (ui *consoleUI) runBlocklistCommand(args []string) {
	if len(args) < 2 {
		ui.appendLog("usage: blocklist add|enable|disable|remove ...")
		return
	}
	d := ui.dad
	action := strings.ToLower(args[0])
	switch action {
	case "add":
		if len(args) < 3 {
			ui.appendLog("usage: blocklist add <name> <source>")
			return
		}
		d.cfg.Blocklists = append(d.cfg.Blocklists, BlocklistSource{Name: args[1], Source: args[2], Enabled: true})
		_ = d.saveConfig()
		ui.appendLog("added blocklist " + args[1])
	case "enable", "disable":
		source := args[1]
		for i := range d.cfg.Blocklists {
			if d.cfg.Blocklists[i].Source == source {
				d.cfg.Blocklists[i].Enabled = action == "enable"
				_ = d.saveConfig()
				ui.appendLog(action + "d blocklist " + source)
				return
			}
		}
		ui.appendLog("blocklist not found")
	case "remove":
		source := args[1]
		next := d.cfg.Blocklists[:0]
		found := false
		for _, list := range d.cfg.Blocklists {
			if list.Source == source {
				found = true
				continue
			}
			next = append(next, list)
		}
		d.cfg.Blocklists = next
		_ = d.saveConfig()
		if found {
			ui.appendLog("removed blocklist " + source)
		} else {
			ui.appendLog("blocklist not found")
		}
	default:
		ui.appendLog("usage: blocklist add|enable|disable|remove ...")
	}
}

func (ui *consoleUI) runWhitelistCommand(args []string) {
	d := ui.dad
	if len(args) == 0 || args[0] == "list" {
		if len(d.cfg.Whitelist) == 0 {
			ui.appendLog("Whitelist is empty.")
			return
		}
		ui.appendLog(strings.Join(d.cfg.Whitelist, "\n"))
		return
	}
	if len(args) < 2 {
		ui.appendLog("usage: whitelist add|remove <ip|cidr>")
		return
	}
	item := strings.TrimSpace(args[1])
	switch strings.ToLower(args[0]) {
	case "add":
		if !ipInList(item, d.cfg.Whitelist) {
			d.cfg.Whitelist = append(d.cfg.Whitelist, item)
			_ = d.saveConfig()
		}
		ui.appendLog("whitelisted " + item)
	case "remove":
		next := d.cfg.Whitelist[:0]
		for _, existing := range d.cfg.Whitelist {
			if existing != item {
				next = append(next, existing)
			}
		}
		d.cfg.Whitelist = next
		_ = d.saveConfig()
		ui.appendLog("removed whitelist entry " + item)
	default:
		ui.appendLog("usage: whitelist add|remove <ip|cidr>")
	}
}

func (ui *consoleUI) runUpstreamsCommand() {
	d := ui.dad
	if len(d.cfg.Upstreams) == 0 {
		ui.appendLog("No upstreams configured.")
		return
	}
	for _, addr := range d.cfg.Upstreams {
		state := "enabled"
		if d.disabledUpstream(addr) {
			state = "disabled"
		}
		ui.appendLog(fmt.Sprintf("%s  %s", addr, state))
	}
}

func (ui *consoleUI) runUpstreamCommand(args []string) {
	if len(args) < 2 {
		ui.appendLog("usage: upstream add|enable|disable|remove <addr>")
		return
	}
	d := ui.dad
	action := strings.ToLower(args[0])
	addr := strings.TrimSpace(args[1])
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	switch action {
	case "add":
		d.cfg.Upstreams = append(d.cfg.Upstreams, addr)
		_ = d.saveConfig()
		ui.appendLog("added upstream " + addr)
	case "enable", "disable":
		next := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != addr {
				next = append(next, item)
			}
		}
		if action == "disable" {
			next = append(next, addr)
		}
		d.cfg.DisabledUpstreams = next
		_ = d.saveConfig()
		ui.appendLog(action + "d upstream " + addr)
	case "remove":
		nextUp := d.cfg.Upstreams[:0]
		for _, item := range d.cfg.Upstreams {
			if item != addr {
				nextUp = append(nextUp, item)
			}
		}
		d.cfg.Upstreams = nextUp
		nextDisabled := d.cfg.DisabledUpstreams[:0]
		for _, item := range d.cfg.DisabledUpstreams {
			if item != addr {
				nextDisabled = append(nextDisabled, item)
			}
		}
		d.cfg.DisabledUpstreams = nextDisabled
		_ = d.saveConfig()
		ui.appendLog("removed upstream " + addr)
	default:
		ui.appendLog("usage: upstream add|enable|disable|remove <addr>")
	}
}
