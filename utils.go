// utils for magicgate

package magicgate

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

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
