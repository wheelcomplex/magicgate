// utils for magicgate

package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// NoSIGHUP will ignore HUP signal
func NoSIGHUP() {
	c := make(chan os.Signal, 8)
	signal.Notify(c, syscall.SIGHUP)
	go func() {
		for s := range c {
			fmt.Printf("NoSIGHUP, ignored: %v\n", s)
		}
	}()
}

// NoSIGPIPE will ignore PIPE signal
func NoSIGPIPE() {
	c := make(chan os.Signal, 8)
	signal.Notify(c, syscall.SIGPIPE)
	go func() {
		for s := range c {
			fmt.Printf("NoSIGPIPE, ignored: %v\n", s)
		}
	}()
}

// NopError represent a error which is not a real error
type NopError struct{}

func (m *NopError) Error() string {
	return "NOP"
}

// IsNopError return true is err is a NopError
func IsNopError(err error) bool {
	return err.Error() == "NOP"
}

// LoopReplaceAll repeatedly replace until nothing changed
func LoopReplaceAll(s, old, new string) string {
	pre := s
	for {
		s = strings.ReplaceAll(s, old, new)
		if pre == s {
			return s
		}
		pre = s
	}
}

// IsAllDotNumber return true when string s include only number and . (check ipv4 address)
func IsAllDotNumber(s string) bool {
	for i := len(s) - 1; i >= 0; i-- {
		// 0 - 9 and .
		if (s[i] > 57 || s[i] < 48) && s[i] != '.' {
			return false
		}
	}
	return true
}

// RandToken generates a random hex value.
// thanks: https://christiangiacomi.com/posts/random-hex-go/
func RandToken(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
