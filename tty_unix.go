//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// withLongLineInput runs read with the terminal's canonical mode disabled,
// because canonical mode caps a line at MAX_CANON bytes (1024 on macOS) and
// silently drops the rest, including the newline, so a pasted token hangs.
func withLongLineInput(read func() (string, error)) (string, error) {
	fd := int(os.Stdin.Fd())
	orig, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return read()
	}
	raw := *orig
	raw.Lflag &^= unix.ICANON
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &raw); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(fd, ioctlSetTermios, orig)
	return read()
}
