package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func (d *DNSLeaf) handleCLI(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "validate" || args[0] == "check-config" {
		d.cfgMu.RLock()
		err := validateConfig(d.cfg)
		schema := d.cfg.SchemaVersion
		d.cfgMu.RUnlock()
		if err != nil {
			fmt.Printf("configuration invalid: %v\n", err)
		} else {
			fmt.Printf("configuration valid (schema %d)\n", schema)
		}
		return true
	}
	if args[0] == "service" {
		return d.handleServiceCLI(args[1:])
	}
	if args[0] != "user" {
		return false
	}
	if len(args) < 2 {
		fmt.Println("usage: dnsleaf user list | add <username> <password> [admin|viewer] | reset <username> <password> | role <username> <admin|viewer> | remove <username>")
		return true
	}
	switch args[1] {
	case "list":
		if len(d.cfg.Auth.Users) == 0 {
			fmt.Println("no users configured")
			return true
		}
		for _, user := range d.cfg.Auth.Users {
			fmt.Printf("%s\t%s\t%s\n", user.Username, user.Role, user.CreatedAt)
		}
	case "add":
		if len(args) < 4 {
			fmt.Println("usage: dnsleaf user add <username> <password> [admin|viewer]")
			return true
		}
		role := "viewer"
		if len(args) >= 5 {
			role = args[4]
		}
		if role != "admin" && role != "viewer" {
			fmt.Println("role must be admin or viewer")
			return true
		}
		if !validUsername(args[2]) || args[3] == "" || len(args[3]) > 4096 {
			fmt.Println("username and password are invalid")
			return true
		}
		if _, ok := d.findUser(args[2]); ok {
			fmt.Println("user already exists")
			return true
		}
		d.cfg.Auth.Enabled = true
		d.cfg.Auth.Users = append(d.cfg.Auth.Users, UserAuth{Username: args[2], PasswordHash: passwordHash(args[3]), Role: role, CreatedAt: time.Now().Format(time.RFC3339)})
		if err := d.saveConfig(); err != nil {
			fmt.Printf("save failed: %v\n", err)
			return true
		}
		fmt.Printf("added %s as %s\n", args[2], role)
	case "reset":
		if len(args) < 4 {
			fmt.Println("usage: dnsleaf user reset <username> <password>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				d.cfg.Auth.Users[i].PasswordHash = passwordHash(args[3])
				if err := d.saveConfig(); err != nil {
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("reset password for %s\n", args[2])
				return true
			}
		}
		fmt.Println("user not found")
	case "role":
		if len(args) < 4 || (args[3] != "admin" && args[3] != "viewer") {
			fmt.Println("usage: dnsleaf user role <username> <admin|viewer>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				if user.Role == "admin" && args[3] != "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot demote the last administrator")
					return true
				}
				d.cfg.Auth.Users[i].Role = args[3]
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users[i] = user
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("updated %s to %s\n", args[2], args[3])
				return true
			}
		}
		fmt.Println("user not found")
	case "remove":
		if len(args) < 3 {
			fmt.Println("usage: dnsleaf user remove <username>")
			return true
		}
		for i, user := range d.cfg.Auth.Users {
			if user.Username == args[2] {
				if len(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot remove the last user")
					return true
				}
				if user.Role == "admin" && adminCount(d.cfg.Auth.Users) <= 1 {
					fmt.Println("cannot remove the last administrator")
					return true
				}
				users := append([]UserAuth(nil), d.cfg.Auth.Users...)
				d.cfg.Auth.Users = append(d.cfg.Auth.Users[:i], d.cfg.Auth.Users[i+1:]...)
				if err := d.saveConfig(); err != nil {
					d.cfg.Auth.Users = users
					fmt.Printf("save failed: %v\n", err)
					return true
				}
				d.revokeUserSessions(user.Username)
				fmt.Printf("removed %s\n", args[2])
				return true
			}
		}
		fmt.Println("user not found")
	default:
		fmt.Println("unknown user command")
	}
	return true
}

func (d *DNSLeaf) handleServiceCLI(args []string) bool {
	if len(args) == 0 {
		fmt.Println("usage: dnsleaf service install | uninstall")
		return true
	}
	switch args[0] {
	case "install":
		if err := d.installLinuxService(); err != nil {
			fmt.Fprintf(os.Stderr, "service install failed: %v\n", err)
			return true
		}
		fmt.Println("installed dnsleaf.service")
		fmt.Println("start with: sudo systemctl enable --now dnsleaf")
	case "uninstall", "remove":
		if err := d.uninstallLinuxService(); err != nil {
			fmt.Fprintf(os.Stderr, "service uninstall failed: %v\n", err)
			return true
		}
		fmt.Println("removed dnsleaf.service")
	default:
		fmt.Println("usage: dnsleaf service install | uninstall")
	}
	return true
}

func (d *DNSLeaf) installLinuxService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd service install is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo ./dnsleaf service install")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	cfgPath, err := filepath.Abs(d.cfgPath)
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=DNSLeaf DNS resolver and admin panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=%s
ExecStart=%s --no-tui --config %s
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
`, systemdEscape(filepath.Dir(cfgPath)), systemdEscape(exe), systemdEscape(cfgPath))
	if err := os.WriteFile("/etc/systemd/system/dnsleaf.service", []byte(unit), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

func (d *DNSLeaf) uninstallLinuxService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("systemd service uninstall is only supported on Linux")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("run as root: sudo ./dnsleaf service uninstall")
	}
	_ = exec.Command("systemctl", "disable", "--now", "dnsleaf").Run()
	if err := os.Remove("/etc/systemd/system/dnsleaf.service"); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "reset-failed", "dnsleaf").Run()
	return nil
}

func systemdEscape(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, " ", `\x20`, "\t", `\x09`, "\n", "")
	return replacer.Replace(value)
}
