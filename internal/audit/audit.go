package audit

import (
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/Star-Trails/sing-redact/internal/jsonx"
	"github.com/Star-Trails/sing-redact/internal/report"
)

var (
	privateKeyPEM = regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)
	obviousJWT    = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	highEntropy   = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)
	secretKey     = regexp.MustCompile(`(?i)(^|_)(password|passwd|passphrase|secret|credential|token|cookie|private_key|pre_shared_key|static_key|client_key|account_key|auth_key|api_key|access_key_secret|security_token|zone_token|origin_ca_key|mac_key|pin|psk|userkey)(_|$)`)
	sensitiveQ    = regexp.MustCompile(`(?i)(^|[_-])(password|passwd|passphrase|secret|credential|token|cookie|api[_-]?key|auth|authorization|access[_-]?key)([_-]|$)`)
	secretPrefix  = regexp.MustCompile(`(?i)^(sk-[a-z0-9_-]{16,}|gh[pousr]_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|AKIA[A-Z0-9]{16}|tskey-[a-z0-9_-]{16,}|cf[a-z0-9_-]{24,})$`)
)

func Scan(root *jsonx.Value, mode string) []report.Finding {
	var findings []report.Finding
	walk(root, nil, "", mode, &findings)
	return report.Dedupe(findings)
}

func walk(value *jsonx.Value, path []any, container, mode string, findings *[]report.Finding) {
	switch value.Kind {
	case jsonx.Object:
		for _, member := range value.Obj {
			memberPath := appendPath(path, member.Key)
			normalized := strings.ReplaceAll(strings.ToLower(member.Key), "-", "_")
			if isSensitiveField(normalized) && hasUnredactedScalar(member.Value) {
				*findings = append(*findings, report.Finding{Category: "CREDENTIAL_REMAINS", Path: jsonx.FormatPath(memberPath)})
			}
			if isHeaderContainer(container) && isSensitiveHeader(member.Key) && hasUnredactedScalar(member.Value) {
				*findings = append(*findings, report.Finding{Category: "AUTHORIZATION_REMAINS", Path: jsonx.FormatPath(memberPath)})
			}
			walk(member.Value, memberPath, member.Key, mode, findings)
		}
	case jsonx.Array:
		for index, child := range value.Arr {
			walk(child, appendPath(path, index), container, mode, findings)
		}
	case jsonx.String:
		scanString(value.Str, path, mode, findings)
	}
}

func scanString(value string, path []any, mode string, findings *[]report.Finding) {
	if isPlaceholder(value) {
		return
	}
	formattedPath := jsonx.FormatPath(path)
	if privateKeyPEM.MatchString(value) {
		*findings = append(*findings, report.Finding{Category: "PRIVATE_KEY_REMAINS", Path: formattedPath})
	}
	if obviousJWT.MatchString(value) {
		*findings = append(*findings, report.Finding{Category: "JWT_REMAINS", Path: formattedPath})
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") {
		*findings = append(*findings, report.Finding{Category: "AUTHORIZATION_REMAINS", Path: formattedPath})
	}
	if strings.Contains(value, "://") && urlContainsCredential(value) {
		*findings = append(*findings, report.Finding{Category: "URL_CREDENTIAL_REMAINS", Path: formattedPath})
	}
	if secretPrefix.MatchString(value) {
		*findings = append(*findings, report.Finding{Category: "SUSPICIOUS_SECRET_PREFIX", Path: formattedPath})
	}
	if looksHighEntropy(value) && !isExpectedPublicMaterial(path, mode) {
		*findings = append(*findings, report.Finding{Category: "SUSPICIOUS_HIGH_ENTROPY", Path: formattedPath})
	}
}

func isExpectedPublicMaterial(path []any, mode string) bool {
	if mode == "strict" {
		return false
	}
	key := lastPathKey(path)
	switch key {
	case "public_key", "host_key", "certificate_public_key_sha256", "client_certificate_public_key_sha256",
		"peer_fingerprint", "fingerprint", "certificate", "certificates", "client_certificate",
		"mca_certificate", "certificate_authority":
		return true
	case "config":
		return pathContains(path, "ech")
	default:
		return false
	}
}

func lastPathKey(path []any) string {
	for index := len(path) - 1; index >= 0; index-- {
		if key, ok := path[index].(string); ok {
			return strings.ToLower(key)
		}
	}
	return ""
}

func pathContains(path []any, expected string) bool {
	for _, segment := range path {
		if key, ok := segment.(string); ok && strings.EqualFold(key, expected) {
			return true
		}
	}
	return false
}

func isSensitiveField(key string) bool {
	if key == "public_key" || key == "certificate_public_key_sha256" || key == "client_certificate_public_key_sha256" || key == "key_type" || key == "key_direction" || key == "host_key_algorithms" {
		return false
	}
	return secretKey.MatchString(key)
}

func isHeaderContainer(value string) bool {
	return strings.EqualFold(value, "headers") || strings.EqualFold(value, "extra_headers")
}

func isSensitiveHeader(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	return strings.Contains(normalized, "authorization") || strings.Contains(normalized, "credential") || strings.Contains(normalized, "password") || strings.Contains(normalized, "passwd") || strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "api_key") || strings.Contains(normalized, "cookie")
}

func hasUnredactedScalar(value *jsonx.Value) bool {
	switch value.Kind {
	case jsonx.String:
		return value.Str != "" && !isPlaceholder(value.Str)
	case jsonx.Array:
		for _, child := range value.Arr {
			if hasUnredactedScalar(child) {
				return true
			}
		}
	}
	return false
}

func isPlaceholder(value string) bool {
	if strings.HasPrefix(value, "<REDACTED:") && strings.HasSuffix(value, ">") {
		return true
	}
	if value == "00000000-0000-4000-8000-000000000000" || value == "0000000000000000" || value == "redacted.example" || value == "redacted@example.com" {
		return true
	}
	return strings.HasSuffix(value, ".redacted.example") || strings.HasPrefix(value, "redacted-process") || strings.HasPrefix(value, "com.example.redacted") || strings.HasPrefix(value, "interface-") || strings.HasPrefix(value, "user-") || strings.HasPrefix(value, "wifi-") || strings.HasPrefix(value, "192.0.2.") || strings.HasPrefix(value, "198.51.100.") || strings.HasPrefix(value, "203.0.113.") || strings.HasPrefix(value, "2001:db8:") || strings.HasPrefix(strings.ToLower(value), "02:00:00:00:")
}

func urlContainsCredential(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if parsed.User != nil {
		return true
	}
	for key, values := range parsed.Query() {
		if sensitiveQ.MatchString(key) {
			for _, value := range values {
				if !isPlaceholder(value) {
					return true
				}
			}
		}
	}
	return false
}

func looksHighEntropy(value string) bool {
	if len(value) < 32 || len(value) > 4096 || strings.Contains(value, "://") || !highEntropy.MatchString(value) {
		return false
	}
	counts := make(map[rune]int)
	var total int
	for _, character := range value {
		counts[character]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		probability := float64(count) / float64(total)
		entropy -= probability * math.Log2(probability)
	}
	return entropy >= 4.2
}

func appendPath(path []any, segment any) []any {
	result := make([]any, len(path)+1)
	copy(result, path)
	result[len(path)] = segment
	return result
}
