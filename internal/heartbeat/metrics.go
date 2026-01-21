package heartbeat

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var startTime = time.Now()

// CollectMetrics collects system metrics.
func CollectMetrics() Metrics {
	return Metrics{
		CPUPercent:    getCPUPercent(),
		MemoryPercent: getMemoryPercent(),
		DiskPercent:   getDiskPercent("/"),
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
	}
}

// getCPUPercent returns the CPU usage percentage.
// This is a simplified implementation that reads from /proc/stat on Linux.
func getCPUPercent() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}

	// Read CPU stats twice with a small interval
	idle1, total1 := readCPUStats()
	time.Sleep(100 * time.Millisecond)
	idle2, total2 := readCPUStats()

	idleDelta := float64(idle2 - idle1)
	totalDelta := float64(total2 - total1)

	if totalDelta == 0 {
		return 0
	}

	return (1.0 - idleDelta/totalDelta) * 100
}

// readCPUStats reads CPU statistics from /proc/stat.
func readCPUStats() (idle, total uint64) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0, 0
			}

			var values []uint64
			for _, field := range fields[1:] {
				val, _ := strconv.ParseUint(field, 10, 64)
				values = append(values, val)
				total += val
			}

			// idle is the 4th field (index 3)
			if len(values) > 3 {
				idle = values[3]
			}
			// Add iowait if present (5th field, index 4)
			if len(values) > 4 {
				idle += values[4]
			}

			return idle, total
		}
	}

	return 0, 0
}

// getMemoryPercent returns the memory usage percentage.
func getMemoryPercent() float64 {
	if runtime.GOOS != "linux" {
		return getMemoryPercentRuntime()
	}

	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return getMemoryPercentRuntime()
	}
	defer file.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		value, _ := strconv.ParseUint(fields[1], 10, 64)

		switch fields[0] {
		case "MemTotal:":
			memTotal = value
		case "MemAvailable:":
			memAvailable = value
		}

		if memTotal > 0 && memAvailable > 0 {
			break
		}
	}

	if memTotal == 0 {
		return 0
	}

	return float64(memTotal-memAvailable) / float64(memTotal) * 100
}

// getMemoryPercentRuntime returns memory usage using Go runtime (fallback).
func getMemoryPercentRuntime() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// This is just the Go heap, not total system memory
	// Return 0 if we can't get accurate system memory
	return 0
}

// getDiskPercent returns the disk usage percentage for the given path.
func getDiskPercent(path string) float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)

	if total == 0 {
		return 0
	}

	used := total - free
	return float64(used) / float64(total) * 100
}
