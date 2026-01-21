package heartbeat

import (
	"runtime"
	"testing"
)

func TestCollectMetrics(t *testing.T) {
	metrics := CollectMetrics()

	// CPU percent should be between 0 and 100
	if metrics.CPUPercent < 0 || metrics.CPUPercent > 100 {
		t.Errorf("CPUPercent = %f, should be between 0 and 100", metrics.CPUPercent)
	}

	// Memory percent should be between 0 and 100
	if metrics.MemoryPercent < 0 || metrics.MemoryPercent > 100 {
		t.Errorf("MemoryPercent = %f, should be between 0 and 100", metrics.MemoryPercent)
	}

	// Disk percent should be between 0 and 100
	if metrics.DiskPercent < 0 || metrics.DiskPercent > 100 {
		t.Errorf("DiskPercent = %f, should be between 0 and 100", metrics.DiskPercent)
	}

	// Uptime should be positive (at least a few milliseconds since startTime was set)
	if metrics.UptimeSeconds < 0 {
		t.Errorf("UptimeSeconds = %d, should be positive", metrics.UptimeSeconds)
	}
}

func TestMetricsOnCurrentPlatform(t *testing.T) {
	metrics := CollectMetrics()

	// On Linux, we should get real values
	if runtime.GOOS == "linux" {
		// Memory should always be detectable
		if metrics.MemoryPercent == 0 {
			t.Log("Warning: MemoryPercent is 0, might indicate /proc/meminfo is not readable")
		}

		// Disk should always be detectable
		if metrics.DiskPercent == 0 {
			t.Log("Warning: DiskPercent is 0, might indicate root filesystem is not readable")
		}
	}

	t.Logf("Collected metrics: CPU=%.2f%%, Memory=%.2f%%, Disk=%.2f%%, Uptime=%ds",
		metrics.CPUPercent, metrics.MemoryPercent, metrics.DiskPercent, metrics.UptimeSeconds)
}
