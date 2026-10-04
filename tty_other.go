//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package main

func withLongLineInput(read func() (string, error)) (string, error) {
	return read()
}
