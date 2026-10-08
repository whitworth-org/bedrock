//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package tty

import "syscall"

// ioctlGetTermios is the ioctl request that reads a terminal's attributes.
const ioctlGetTermios = syscall.TIOCGETA
