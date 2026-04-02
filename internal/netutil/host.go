package netutil

import (
	"net"
	"strings"
)

func NormalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func IsLoopbackHost(host string) bool {
	normalized := NormalizeHostname(host)
	if normalized == "localhost" {
		return true
	}

	ip := net.ParseIP(normalized)
	return ip != nil && ip.IsLoopback()
}
