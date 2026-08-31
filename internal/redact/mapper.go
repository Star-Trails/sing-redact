package redact

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/Star-Trails/sing-redact/internal/jsonx"
)

type Mapper struct {
	values   map[string]map[string]string
	counters map[string]int
}

func NewMapper() *Mapper {
	return &Mapper{
		values:   make(map[string]map[string]string),
		counters: make(map[string]int),
	}
}

func (m *Mapper) mapped(kind, original string, build func(int) string) string {
	bucket := m.values[kind]
	if bucket == nil {
		bucket = make(map[string]string)
		m.values[kind] = bucket
	}
	if replacement, exists := bucket[original]; exists {
		return replacement
	}
	m.counters[kind]++
	replacement := build(m.counters[kind])
	bucket[original] = replacement
	return replacement
}

func (m *Mapper) domain(original string, preferPlain bool) string {
	bucket := m.values["domain"]
	if bucket != nil {
		if replacement, exists := bucket[strings.ToLower(original)]; exists {
			return replacement
		}
	}
	return m.mapped("domain", strings.ToLower(original), func(index int) string {
		if preferPlain && index == 1 {
			return "redacted.example"
		}
		return fmt.Sprintf("domain-%d.redacted.example", index)
	})
}

func (m *Mapper) ipv4(original string) string {
	return m.mapped("ipv4", original, func(index int) string {
		block := (index - 1) / 254
		host := ((index - 1) % 254) + 1
		switch block {
		case 0:
			return fmt.Sprintf("192.0.2.%d", host)
		case 1:
			return fmt.Sprintf("198.51.100.%d", host)
		case 2:
			return fmt.Sprintf("203.0.113.%d", host)
		default:
			offset := index - 763
			second := 18 + offset/(256*254)
			if second > 19 {
				return "0.0.0.0"
			}
			remainder := offset % (256 * 254)
			return fmt.Sprintf("198.%d.%d.%d", second, remainder/254, remainder%254+1)
		}
	})
}

func (m *Mapper) ipv6(original string) string {
	return m.mapped("ipv6", original, func(index int) string {
		if index <= 0xffff {
			return fmt.Sprintf("2001:db8::%x", index)
		}
		return fmt.Sprintf("2001:db8::%x:%x:%x:%x", (index>>48)&0xffff, (index>>32)&0xffff, (index>>16)&0xffff, index&0xffff)
	})
}

func (m *Mapper) identity(original string) string {
	if strings.Contains(original, "@") {
		return m.mapped("email", strings.ToLower(original), func(index int) string {
			if index == 1 {
				return "redacted@example.com"
			}
			return fmt.Sprintf("user-%d@redacted.example", index)
		})
	}
	return m.mapped("identity", original, func(index int) string { return fmt.Sprintf("user-%d", index) })
}

func (m *Mapper) process(original string) string {
	return m.mapped("process", original, func(index int) string {
		if index == 1 {
			return "redacted-process"
		}
		return fmt.Sprintf("redacted-process-%d", index)
	})
}

func (m *Mapper) packageName(original string) string {
	return m.mapped("package", original, func(index int) string {
		if index == 1 {
			return "com.example.redacted"
		}
		return fmt.Sprintf("com.example.redacted%d", index)
	})
}

func (m *Mapper) wifi(original string) string {
	return m.mapped("wifi", original, func(index int) string { return fmt.Sprintf("wifi-%d", index) })
}

func (m *Mapper) mac(original string) string {
	return m.mapped("mac", strings.ToLower(original), func(index int) string {
		return fmt.Sprintf("02:00:00:00:%02x:%02x", (index>>8)&0xff, index&0xff)
	})
}

func (m *Mapper) objectKey(action, original string) string {
	switch action {
	case "KEY_SNI":
		return m.mapped("sni-key", strings.ToLower(original), func(index int) string {
			return fmt.Sprintf("sni-%d.redacted.example", index)
		})
	case "KEY_HOST":
		return m.mapped("host-key", strings.ToLower(original), func(index int) string {
			return fmt.Sprintf("host-%d.redacted.example", index)
		})
	case "KEY_INTERFACE":
		return m.mapped("interface-key", original, func(index int) string {
			return fmt.Sprintf("interface-%d", index)
		})
	default:
		return original
	}
}

func isOwnPlaceholder(value string) bool {
	if strings.HasPrefix(value, "<REDACTED:") && strings.HasSuffix(value, ">") {
		return true
	}
	if value == "00000000-0000-4000-8000-000000000000" || value == "0000000000000000" || value == "redacted.example" || value == "redacted@example.com" {
		return true
	}
	if strings.HasSuffix(value, ".redacted.example") || strings.HasPrefix(value, "redacted-process") || strings.HasPrefix(value, "com.example.redacted") || strings.HasPrefix(value, "interface-") || strings.HasPrefix(value, "user-") || strings.HasPrefix(value, "wifi-") {
		return true
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Is4() && (address.IsPrivate() == false) && (strings.HasPrefix(value, "192.0.2.") || strings.HasPrefix(value, "198.51.100.") || strings.HasPrefix(value, "203.0.113.")) || address.Is6() && strings.HasPrefix(value, "2001:db8:")
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return strings.HasPrefix(prefix.String(), "192.0.2.") || strings.HasPrefix(prefix.String(), "198.51.100.") || strings.HasPrefix(prefix.String(), "203.0.113.") || strings.HasPrefix(prefix.String(), "2001:db8:")
	}
	return ownMACPattern.MatchString(value)
}

var ownMACPattern = regexp.MustCompile(`(?i)^02:00:00:00:[0-9a-f]{2}:[0-9a-f]{2}$`)

func (m *Mapper) replace(action string, value *jsonx.Value) bool {
	if value == nil || value.Kind == jsonx.Null {
		return false
	}
	if value.Kind == jsonx.Array {
		if (action == "PRIVATE_KEY" || action == "CERTIFICATE") && len(value.Arr) > 0 {
			placeholder := "<REDACTED:PRIVATE_KEY>"
			if action == "CERTIFICATE" {
				placeholder = "<REDACTED:CERTIFICATE>"
			}
			if len(value.Arr) == 1 && value.Arr[0].Kind == jsonx.String && value.Arr[0].Str == placeholder {
				return false
			}
			value.Arr = []*jsonx.Value{{Kind: jsonx.String, Str: placeholder}}
			return true
		}
		changed := false
		for _, child := range value.Arr {
			if m.replace(action, child) {
				changed = true
			}
		}
		return changed
	}
	if value.Kind == jsonx.Object {
		return false
	}
	if value.Kind == jsonx.Number {
		if memberAction(action, "IDENTITY", "FINGERPRINT", "NETWORK") && value.Num.String() != "0" {
			value.Num = "0"
			return true
		}
		return false
	}
	if value.Kind == jsonx.Bool {
		return false
	}
	if value.Kind != jsonx.String || isOwnPlaceholder(value.Str) {
		return false
	}
	original := value.Str
	replacement := original
	switch action {
	case "PASSWORD":
		replacement = "<REDACTED:PASSWORD>"
	case "PRIVATE_KEY":
		replacement = "<REDACTED:PRIVATE_KEY>"
	case "PSK":
		replacement = "<REDACTED:PSK>"
	case "KEY":
		replacement = "<REDACTED:KEY>"
	case "SECRET":
		replacement = "<REDACTED:SECRET>"
	case "TOKEN":
		replacement = "<REDACTED:TOKEN>"
	case "COOKIE":
		replacement = "<REDACTED:COOKIE>"
	case "AUTHORIZATION":
		replacement = "<REDACTED:AUTHORIZATION>"
	case "CREDENTIAL":
		replacement = "<REDACTED:CREDENTIAL>"
	case "UUID":
		replacement = "00000000-0000-4000-8000-000000000000"
	case "SHORT_ID":
		replacement = "0000000000000000"
	case "PATH":
		replacement = "<REDACTED:PATH>"
	case "CERTIFICATE":
		replacement = "<REDACTED:CERTIFICATE>"
	case "FINGERPRINT":
		replacement = "<REDACTED:FINGERPRINT>"
	case "IDENTITY":
		replacement = m.identity(original)
	case "PROCESS":
		replacement = m.process(original)
	case "PACKAGE":
		replacement = m.packageName(original)
	case "WIFI":
		replacement = m.wifi(original)
	case "MAC":
		replacement = m.mac(original)
	case "DOMAIN":
		replacement = m.domain(original, false)
	case "DOMAIN_REGEX":
		replacement = `^redacted\.example$`
	case "ENDPOINT":
		replacement = m.endpoint(original)
	case "NETWORK":
		replacement = m.network(original)
	case "PRIVATE_NETWORK":
		replacement = m.privateNetwork(original)
	case "URL_SANITIZE":
		replacement = sanitizeURL(original, false)
	case "URL_ENDPOINT", "URL_STRICT":
		replacement = sanitizeURL(original, true)
	}
	if replacement == original {
		return false
	}
	value.Str = replacement
	return true
}

func memberAction(action string, values ...string) bool {
	for _, value := range values {
		if action == value {
			return true
		}
	}
	return false
}

func (m *Mapper) endpoint(original string) string {
	if isOwnPlaceholder(original) {
		return original
	}
	if strings.Contains(original, "://") {
		return sanitizeURL(original, true)
	}
	if host, port, err := net.SplitHostPort(original); err == nil {
		return net.JoinHostPort(m.host(host, true), port)
	}
	return m.host(original, true)
}

func (m *Mapper) network(original string) string {
	if isOwnPlaceholder(original) {
		return original
	}
	if prefix, err := netip.ParsePrefix(original); err == nil {
		if prefix.Addr().Is4() {
			return m.ipv4(prefix.Masked().Addr().String()) + "/24"
		}
		return "2001:db8::/32"
	}
	if host, port, err := net.SplitHostPort(original); err == nil {
		return net.JoinHostPort(m.host(host, true), port)
	}
	return m.host(original, true)
}

func (m *Mapper) privateNetwork(original string) string {
	if prefix, err := netip.ParsePrefix(original); err == nil {
		if isPrivateAddress(prefix.Addr()) {
			return m.network(original)
		}
		return original
	}
	if address, err := netip.ParseAddr(strings.Trim(original, "[]")); err == nil {
		if isPrivateAddress(address) {
			return m.network(original)
		}
		return original
	}
	if host, _, err := net.SplitHostPort(original); err == nil {
		if address, parseErr := netip.ParseAddr(strings.Trim(host, "[]")); parseErr == nil && isPrivateAddress(address) {
			return m.network(original)
		}
	}
	return original
}

func isPrivateAddress(address netip.Addr) bool {
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified()
}

func (m *Mapper) host(original string, preferPlain bool) string {
	trimmed := strings.Trim(original, "[]")
	if isOwnPlaceholder(trimmed) {
		return trimmed
	}
	if address, err := netip.ParseAddr(trimmed); err == nil {
		if address.Is4() {
			return m.ipv4(address.String())
		}
		return m.ipv6(address.String())
	}
	if strings.Contains(trimmed, "/") {
		if prefix, err := netip.ParsePrefix(trimmed); err == nil {
			if prefix.Addr().Is4() {
				return m.ipv4(prefix.Masked().Addr().String()) + "/24"
			}
			return "2001:db8::/32"
		}
	}
	if _, err := strconv.Atoi(trimmed); err == nil {
		return trimmed
	}
	return m.domain(trimmed, preferPlain)
}
