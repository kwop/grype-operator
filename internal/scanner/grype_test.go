package scanner

import (
	"testing"
)

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{"Critical", 4},
		{"High", 3},
		{"Medium", 2},
		{"Low", 1},
		{"Unknown", 0},
		{"Negligible", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityLevel(tt.severity)
			if got != tt.expected {
				t.Errorf("severityLevel(%q) = %d, want %d", tt.severity, got, tt.expected)
			}
		})
	}
}

func TestParseMatches_Empty(t *testing.T) {
	vulns, summary := parseMatches(nil, "")
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulns, got %d", len(vulns))
	}
	if summary.Critical != 0 || summary.High != 0 || summary.Medium != 0 || summary.Low != 0 {
		t.Error("expected all summary counts to be 0")
	}
}

func TestParseMatches_CountsBySeverity(t *testing.T) {
	matches := []Match{
		{Vulnerability: MatchVuln{ID: "CVE-1", Severity: "Critical"}, Artifact: MatchArtif{Name: "pkg1", Version: "1.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-2", Severity: "Critical"}, Artifact: MatchArtif{Name: "pkg2", Version: "2.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-3", Severity: "High"}, Artifact: MatchArtif{Name: "pkg3", Version: "3.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-4", Severity: "Medium"}, Artifact: MatchArtif{Name: "pkg4", Version: "4.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-5", Severity: "Low"}, Artifact: MatchArtif{Name: "pkg5", Version: "5.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-6", Severity: "Unknown"}, Artifact: MatchArtif{Name: "pkg6", Version: "6.0"}},
	}

	_, summary := parseMatches(matches, "")

	if summary.Critical != 2 {
		t.Errorf("expected 2 critical, got %d", summary.Critical)
	}
	if summary.High != 1 {
		t.Errorf("expected 1 high, got %d", summary.High)
	}
	if summary.Medium != 1 {
		t.Errorf("expected 1 medium, got %d", summary.Medium)
	}
	if summary.Low != 1 {
		t.Errorf("expected 1 low, got %d", summary.Low)
	}
	if summary.Unknown != 1 {
		t.Errorf("expected 1 unknown, got %d", summary.Unknown)
	}
}

func TestParseMatches_MinSeverityFilter(t *testing.T) {
	matches := []Match{
		{Vulnerability: MatchVuln{ID: "CVE-1", Severity: "Critical"}, Artifact: MatchArtif{Name: "pkg1", Version: "1.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-2", Severity: "High"}, Artifact: MatchArtif{Name: "pkg2", Version: "2.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-3", Severity: "Medium"}, Artifact: MatchArtif{Name: "pkg3", Version: "3.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-4", Severity: "Low"}, Artifact: MatchArtif{Name: "pkg4", Version: "4.0"}},
	}

	// minSeverity=High → only Critical and High in vulns list
	vulns, summary := parseMatches(matches, "High")

	if len(vulns) != 2 {
		t.Errorf("expected 2 vulns with minSeverity=High, got %d", len(vulns))
	}

	// Summary should still count all
	if summary.Critical != 1 || summary.High != 1 || summary.Medium != 1 || summary.Low != 1 {
		t.Error("summary should count all vulnerabilities regardless of filter")
	}

	// Verify filtered vulns are correct
	for _, v := range vulns {
		if v.Severity != SevCritical && v.Severity != SevHigh {
			t.Errorf("unexpected severity %q in filtered results", v.Severity)
		}
	}
}

func TestParseMatches_MinSeverityCritical(t *testing.T) {
	matches := []Match{
		{Vulnerability: MatchVuln{ID: "CVE-1", Severity: "Critical"}, Artifact: MatchArtif{Name: "pkg1", Version: "1.0"}},
		{Vulnerability: MatchVuln{ID: "CVE-2", Severity: "High"}, Artifact: MatchArtif{Name: "pkg2", Version: "2.0"}},
	}

	vulns, _ := parseMatches(matches, "Critical")

	if len(vulns) != 1 {
		t.Errorf("expected 1 vuln with minSeverity=Critical, got %d", len(vulns))
	}
	if len(vulns) > 0 && vulns[0].ID != "CVE-1" {
		t.Errorf("expected CVE-1, got %s", vulns[0].ID)
	}
}

func TestParseMatches_FixVersionExtracted(t *testing.T) {
	matches := []Match{
		{
			Vulnerability: MatchVuln{
				ID:       "CVE-1",
				Severity: "High",
				Fix: struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				}{
					Versions: []string{"1.2.3", "1.2.4"},
					State:    "fixed",
				},
			},
			Artifact: MatchArtif{Name: "pkg1", Version: "1.0"},
		},
	}

	vulns, _ := parseMatches(matches, "")

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].FixedIn != "1.2.3" {
		t.Errorf("expected fixedIn '1.2.3', got %q", vulns[0].FixedIn)
	}
}

func TestParseMatches_NoFixVersion(t *testing.T) {
	matches := []Match{
		{
			Vulnerability: MatchVuln{ID: "CVE-1", Severity: "Medium"},
			Artifact:      MatchArtif{Name: "pkg1", Version: "1.0"},
		},
	}

	vulns, _ := parseMatches(matches, "")

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].FixedIn != "" {
		t.Errorf("expected empty fixedIn, got %q", vulns[0].FixedIn)
	}
}

func TestParseMatches_VulnFields(t *testing.T) {
	matches := []Match{
		{
			Vulnerability: MatchVuln{ID: "CVE-2024-12345", Severity: "Critical"},
			Artifact:      MatchArtif{Name: "openssl", Version: "3.0.1"},
		},
	}

	vulns, _ := parseMatches(matches, "")

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	v := vulns[0]
	if v.ID != "CVE-2024-12345" {
		t.Errorf("expected ID CVE-2024-12345, got %q", v.ID)
	}
	if v.Package != "openssl" {
		t.Errorf("expected package openssl, got %q", v.Package)
	}
	if v.Version != "3.0.1" {
		t.Errorf("expected version 3.0.1, got %q", v.Version)
	}
}

func TestNew_Scanner(t *testing.T) {
	s := New(30000000000, "high") // 30s
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
	if s.MinSeverity != "high" {
		t.Errorf("expected MinSeverity 'high', got %q", s.MinSeverity)
	}
}
