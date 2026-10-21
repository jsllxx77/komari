package security

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"

	"github.com/komari-monitor/komari/internal/config"
)

func SplitAllowlist(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		entry := strings.TrimSpace(part)
		if entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

func OriginMatchesHost(origin, host string) bool {
	_, originHost, ok := normalizeOrigin(origin)
	return ok && strings.EqualFold(originHost, host)
}

// OriginInAllowlist reports whether origin is allowed by rawAllowlist. The
// second return value is true only when the match came from a "*" entry, so
// callers can avoid sending credentials for wildcard matches.
//
// Exact entries are evaluated first so an explicitly listed Origin keeps the
// credentialed behavior even when a wildcard is configured alongside it.
func OriginInAllowlist(origin, rawAllowlist string) (matched bool, viaWildcard bool) {
	normalizedOrigin, originHost, ok := normalizeOrigin(origin)
	if !ok {
		return false, false
	}
	entries := SplitAllowlist(rawAllowlist)
	for _, entry := range entries {
		if entry == "*" {
			continue
		}
		if strings.Contains(entry, "://") {
			normalizedEntry, _, ok := normalizeOrigin(entry)
			if ok && strings.EqualFold(normalizedEntry, normalizedOrigin) {
				return true, false
			}
			continue
		}
		if strings.EqualFold(entry, originHost) {
			return true, false
		}
	}
	for _, entry := range entries {
		if entry == "*" {
			return true, true
		}
	}
	return false, false
}

func IsAPIKeyRequest(r *http.Request) bool {
	apiKeyConfig, err := config.GetAs[string](config.ApiKeyKey, "")
	if err != nil || apiKeyConfig == "" || len(apiKeyConfig) < 12 {
		return false
	}
	// Constant-time comparison so the Authorization header cannot be recovered
	// byte by byte from response timing. Lengths are not secret.
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+apiKeyConfig)) == 1
}

func IsAuthorizationPreflight(r *http.Request) bool {
	if r.Method != http.MethodOptions {
		return false
	}
	for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
		if strings.EqualFold(strings.TrimSpace(header), "authorization") {
			return true
		}
	}
	return false
}

func normalizeOrigin(raw string) (string, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", false
	}
	host := strings.ToLower(parsed.Host)
	return strings.ToLower(parsed.Scheme) + "://" + host, host, true
}
