package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/tuannvm/mcp-trino/internal/netutil"
)

func validateExternalAuthMode(scheme, host, transport string) error {
	switch {
	case strings.EqualFold(scheme, "https"):
	case strings.EqualFold(scheme, "http"):
		if !netutil.IsLoopbackHost(host) {
			return fmt.Errorf("TRINO_AUTH_MODE=external requires TRINO_SCHEME=https unless TRINO_HOST is loopback; refusing cleartext HTTP for host %q", host)
		}
		log.Printf("WARNING: TRINO_AUTH_MODE=external over HTTP is allowed only for loopback host %q", host)
	default:
		return fmt.Errorf("TRINO_AUTH_MODE=external requires TRINO_SCHEME to be https, or http only for loopback TRINO_HOST; got %q", scheme)
	}

	if strings.EqualFold(transport, "http") {
		return fmt.Errorf("TRINO_AUTH_MODE=external requires MCP_TRANSPORT=stdio; refusing MCP_TRANSPORT=http because external browser auth is local and process-scoped")
	}
	log.Println("INFO: Trino auth mode: external (Trino browser challenge with cached bearer token)")
	return nil
}
