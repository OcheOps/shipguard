package normalize

import (
	"strings"

	"github.com/OcheOps/shipguard/internal/trivy"
)

type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevUnknown  Severity = "UNKNOWN"
)

type Finding struct {
	ID              string
	Package         string
	Installed       string
	Fixed           string
	Severity        Severity
	FixAvailable    bool
	RuntimeRelevant bool
	Title           string
	URL             string
	Targets         []string // which Trivy "Target" this appeared in
}

func Normalize(r *trivy.Report) []Finding {
	// de-dupe by (CVE + package)
	type key struct{ id, pkg string }
	m := map[key]*Finding{}

	for _, res := range r.Results {
		for _, v := range res.Vulnerabilities {
			k := key{id: v.VulnerabilityID, pkg: v.PkgName}
			if _, ok := m[k]; !ok {
				fx := strings.TrimSpace(v.FixedVersion)
				m[k] = &Finding{
					ID:              v.VulnerabilityID,
					Package:         v.PkgName,
					Installed:       v.InstalledVersion,
					Fixed:           v.FixedVersion,
					Severity:        toSeverity(v.Severity),
					FixAvailable:    fx != "",
					RuntimeRelevant: true, // MVP default; later we can infer better
					Title:           v.Title,
					URL:             v.PrimaryURL,
					Targets:         []string{},
				}
			}
			m[k].Targets = appendUnique(m[k].Targets, res.Target)
		}
	}

	out := make([]Finding, 0, len(m))
	for _, f := range m {
		out = append(out, *f)
	}
	return out
}

func toSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical
	case "HIGH":
		return SevHigh
	case "MEDIUM":
		return SevMedium
	case "LOW":
		return SevLow
	default:
		return SevUnknown
	}
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}
