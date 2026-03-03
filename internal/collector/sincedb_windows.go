//go:build windows

package collector

import (
	"fmt"
	"os"
	"syscall"
)

// GetFileIdentity returns a file identity using the Windows file index.
func GetFileIdentity(path string) (inode, device uint64, err error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid path: %w", err)
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		0, // query only
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		// Fallback: use modification time as identity
		info, statErr := os.Stat(path)
		if statErr != nil {
			return 0, 0, statErr
		}
		return uint64(info.ModTime().UnixNano()), 0, nil
	}
	defer syscall.CloseHandle(handle)

	var fileInfo syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		return 0, 0, fmt.Errorf("getting file information: %w", err)
	}

	fileIndex := uint64(fileInfo.FileIndexHigh)<<32 | uint64(fileInfo.FileIndexLow)
	volumeSerial := uint64(fileInfo.VolumeSerialNumber)

	return fileIndex, volumeSerial, nil
}
