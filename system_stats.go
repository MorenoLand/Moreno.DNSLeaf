package main

import (
	"os"
	"runtime"
	"sync"
	"time"
)

type systemStats struct {
	Hostname string
	Temp     string
	CPU      string
	Memory   string
}

var cpuSample struct {
	sync.Mutex
	total uint64
	idle  uint64
	seen  bool
}

var processCPUSample struct {
	sync.Mutex
	cpuSeconds float64
	wall       time.Time
	seen       bool
}

func collectSystemStats() systemStats {
	host, _ := os.Hostname()
	s := systemStats{Hostname: host, Temp: "n/a", CPU: "n/a", Memory: "n/a"}
	switch runtime.GOOS {
	case "linux":
		s.Temp = linuxTemp()
		s.CPU = processCPUPercent()
		s.Memory = linuxMemory()
	case "windows":
		s.Temp = windowsTemp()
		s.CPU = processCPUPercent()
		s.Memory = windowsMemory()
	}
	return s
}
