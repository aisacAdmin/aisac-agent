//go:build !windows

package collector

import (
	"fmt"
	"os"
	"syscall"
)

// GetFileIdentity returns the inode and device ID for a file.
func GetFileIdentity(path string) (inode, device uint64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("unable to get file identity on this platform")
	}

	return stat.Ino, uint64(stat.Dev), nil
}
