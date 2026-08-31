package redact

import (
	"net/url"
	"regexp"
	"strings"
)

var sensitiveQueryKey = regexp.MustCompile(`(?i)(^|[_-])(password|passwd|passphrase|secret|credential|token|cookie|api[_-]?key|auth|authorization|access[_-]?key)([_-]|$)`)

func sanitizeURL(raw string, replaceEndpoint bool) string {
	if isOwnPlaceholder(raw) {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return raw
	}
	changed := false
	if parsed.User != nil {
		parsed.User = nil
		changed = true
	}
	query := parsed.Query()
	for key := range query {
		if sensitiveQueryKey.MatchString(key) {
			query.Set(key, "<REDACTED:SECRET>")
			changed = true
		}
	}
	if changed {
		parsed.RawQuery = query.Encode()
	}
	if replaceEndpoint && !isPublicDocumentationURL(parsed) {
		return "https://redacted.example/"
	}
	if !changed {
		return raw
	}
	return parsed.String()
}

func isPublicDocumentationURL(parsed *url.URL) bool {
	host := strings.ToLower(parsed.Hostname())
	return host == "sing-box.sagernet.org" && parsed.User == nil
}
