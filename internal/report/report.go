package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

type Finding struct {
	Category string
	Path     string
}

func Dedupe(findings []Finding) []Finding {
	seen := make(map[string]struct{}, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		key := finding.Category + "\x00" + finding.Path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, finding)
	}
	return result
}

func Sort(findings []Finding) {
	sort.SliceStable(findings, func(left, right int) bool {
		if findings[left].Path == findings[right].Path {
			return findings[left].Category < findings[right].Category
		}
		return findings[left].Path < findings[right].Path
	})
}

func WriteRedactions(writer io.Writer, findings []Finding) {
	findings = Dedupe(findings)
	Sort(findings)
	fmt.Fprintf(writer, "Redacted %d values:\n", len(findings))
	for _, finding := range findings {
		fmt.Fprintf(writer, "%-16s %s\n", finding.Category, finding.Path)
	}
}

func WriteAudit(writer io.Writer, title string, findings []Finding) {
	findings = Dedupe(findings)
	Sort(findings)
	fmt.Fprintf(writer, "%s %d findings:\n", title, len(findings))
	for _, finding := range findings {
		fmt.Fprintf(writer, "%-24s %s\n", finding.Category, finding.Path)
	}
}

func WriteCheck(writer io.Writer, findings []Finding) {
	counts := map[string]int{
		"Credentials":  0,
		"Private keys": 0,
		"Endpoints":    0,
		"Identifiers":  0,
		"Paths":        0,
		"Suspicious":   0,
	}
	for _, finding := range Dedupe(findings) {
		switch strings.ToUpper(finding.Category) {
		case "PRIVATE_KEY", "PSK":
			counts["Private keys"]++
		case "ENDPOINT", "URL":
			counts["Endpoints"]++
		case "IDENTITY", "LOCAL_NETWORK", "FINGERPRINT":
			counts["Identifiers"]++
		case "PATH":
			counts["Paths"]++
		case "SUSPICIOUS_HIGH_ENTROPY", "SUSPICIOUS_SECRET_PREFIX", "SUSPICIOUS":
			counts["Suspicious"]++
		default:
			counts["Credentials"]++
		}
	}
	for _, label := range []string{"Credentials", "Private keys", "Endpoints", "Identifiers", "Paths", "Suspicious"} {
		fmt.Fprintf(writer, "%-14s %d\n", label+":", counts[label])
	}
}
