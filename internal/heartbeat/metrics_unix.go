//go:build !windows

package heartbeat

import "syscall"

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
