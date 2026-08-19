package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func processMemory() string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	return fmt.Sprintf("%.1f MB", float64(mem.Alloc)/1024/1024)
}

func processCPUPercent() string {
	seconds, ok := processCPUSeconds()
	if !ok {
		return "n/a"
	}
	now := time.Now()
	processCPUSample.Lock()
	defer processCPUSample.Unlock()
	if !processCPUSample.seen {
		processCPUSample.cpuSeconds = seconds
		processCPUSample.wall = now
		processCPUSample.seen = true
		return "sampling"
	}
	wall := now.Sub(processCPUSample.wall).Seconds()
	cpu := seconds - processCPUSample.cpuSeconds
	processCPUSample.cpuSeconds = seconds
	processCPUSample.wall = now
	if wall <= 0 || cpu < 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", cpu/wall*100)
}

func processCPUSeconds() (float64, bool) {
	switch runtime.GOOS {
	case "linux":
		raw, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			return 0, false
		}
		text := string(raw)
		idx := strings.LastIndex(text, ") ")
		if idx < 0 || idx+2 >= len(text) {
			return 0, false
		}
		fields := strings.Fields(text[idx+2:])
		if len(fields) < 13 {
			return 0, false
		}
		utime, err1 := strconv.ParseFloat(fields[11], 64)
		stime, err2 := strconv.ParseFloat(fields[12], 64)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return (utime + stime) / 100.0, true
	case "windows":
		ps := fmt.Sprintf("(Get-Process -Id %d).CPU", os.Getpid())
		out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
		if err != nil {
			return 0, false
		}
		seconds, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		return seconds, err == nil
	default:
		return 0, false
	}
}

func linuxTemp() string {
	matches, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
		if err != nil {
			continue
		}
		if v > 1000 {
			v = v / 1000
		}
		if v > 0 {
			return fmt.Sprintf("%.1f C", v)
		}
	}
	return "n/a"
}

func linuxCPUPercent() string {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return "n/a"
	}
	fields := strings.Fields(strings.SplitN(string(raw), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return "n/a"
	}
	vals := make([]uint64, 0, len(fields)-1)
	for _, field := range fields[1:] {
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return "n/a"
		}
		vals = append(vals, v)
	}
	var total uint64
	for _, v := range vals {
		total += v
	}
	idle := vals[3]
	if len(vals) > 4 {
		idle += vals[4]
	}
	return cpuPercentFromSample(total, idle)
}

func linuxMemory() string {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return "n/a"
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err == nil {
			values[strings.TrimSuffix(fields[0], ":")] = v
		}
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	if total == 0 || available == 0 {
		return "n/a"
	}
	used := total - available
	return fmt.Sprintf("%.1f / %.1f GB", float64(used)/1024/1024, float64(total)/1024/1024)
}

func windowsCPUPercent() string {
	out, err := exec.Command("typeperf", `\Processor(_Total)\% Processor Time`, "-sc", "1").Output()
	if err != nil {
		return "n/a"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, `"(`) || !strings.Contains(line, ",") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		v := strings.Trim(parts[len(parts)-1], `" `)
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return fmt.Sprintf("%.1f%%", f)
		}
	}
	return "n/a"
}

func windowsMemory() string {
	ps := `Add-Type -AssemblyName Microsoft.VisualBasic; $c=New-Object Microsoft.VisualBasic.Devices.ComputerInfo; "$($c.TotalPhysicalMemory),$($c.AvailablePhysicalMemory)"`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return "n/a"
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ",")
	if len(parts) < 2 {
		return "n/a"
	}
	total, _ := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 64)
	free, _ := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
	if total == 0 {
		return "n/a"
	}
	used := total - free
	return fmt.Sprintf("%.1f / %.1f GB", float64(used)/1024/1024/1024, float64(total)/1024/1024/1024)
}

func windowsTemp() string {
	ps := `try { Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop | Select-Object -First 1 -ExpandProperty CurrentTemperature } catch { "" }`
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()
	if err != nil {
		return "n/a"
	}
	raw, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil || raw <= 0 {
		return "n/a"
	}
	c := raw/10 - 273.15
	if c > -50 && c < 150 {
		return fmt.Sprintf("%.1f C", c)
	}
	return "n/a"
}

func cpuPercentFromSample(total, idle uint64) string {
	cpuSample.Lock()
	defer cpuSample.Unlock()
	if !cpuSample.seen {
		cpuSample.total, cpuSample.idle, cpuSample.seen = total, idle, true
		return "sampling"
	}
	dTotal := total - cpuSample.total
	dIdle := idle - cpuSample.idle
	cpuSample.total, cpuSample.idle = total, idle
	if dTotal == 0 {
		return "0.0%"
	}
	used := float64(dTotal-dIdle) / float64(dTotal) * 100
	return fmt.Sprintf("%.1f%%", used)
}
