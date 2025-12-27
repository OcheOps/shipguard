package trivy

import (
	"encoding/json"
	"fmt"
	"os"
)

type Report struct {
	Results []Result `json:"Results"`
}

type Result struct {
	Target          string           `json:"Target"`
	Type            string           `json:"Type"`
	Vulnerabilities []Vulnerability  `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID   string `json:"VulnerabilityID"`
	PkgName           string `json:"PkgName"`
	InstalledVersion  string `json:"InstalledVersion"`
	FixedVersion      string `json:"FixedVersion"`
	Severity          string `json:"Severity"`
	Title             string `json:"Title"`
	PrimaryURL        string `json:"PrimaryURL"`
}

func LoadReportFromFile(path string) (*Report, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trivy report: %w", err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}
	return &r, nil
}
