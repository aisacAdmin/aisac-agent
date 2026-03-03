//go:build windows

package heartbeat

import (
	"syscall"
	"unsafe"
)

// getDiskPercent returns the disk usage percentage for the given path.
func getDiskPercent(path string) float64 {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")

	var freeBytesAvailable, totalBytes, totalFreeBytes uint64
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0
	}

	ret, _, _ := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if ret == 0 {
		return 0
	}

	if totalBytes == 0 {
		return 0
	}

	used := totalBytes - totalFreeBytes
	return float64(used) / float64(totalBytes) * 100
}
