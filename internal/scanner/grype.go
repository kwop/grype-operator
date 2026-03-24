package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Result holds the parsed output of a Grype scan.
type Result struct {
	Matches []Match `json:"matches"`
}

// Match represents a single vulnerability match from Grype JSON output.
type Match struct {
	Vulnerability MatchVuln  `json:"vulnerability"`
	Artifact      MatchArtif `json:"artifact"`
}

type MatchVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Fix      struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`
}

type MatchArtif struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// VulnItem is a simplified vulnerability for the CRD status.
type VulnItem struct {
	ID       string
	Severity string
	Package  string
	Version  string
	FixedIn  string
}

// Summary holds vulnerability counts by severity.
type Summary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Unknown  int
}

// Scanner executes Grype scans on container images.
type Scanner struct {
	Timeout     time.Duration
	MinSeverity string
}

// New creates a Scanner with the given timeout.
func New(timeout time.Duration, minSeverity string) *Scanner {
	return &Scanner{Timeout: timeout, MinSeverity: minSeverity}
}

// Scan runs grype on the given image reference and returns parsed results.
func (s *Scanner) Scan(ctx context.Context, imageRef string) ([]VulnItem, *Summary, error) {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	args := []string{imageRef, "-o", "json", "--quiet"}
	if s.MinSeverity != "" {
		args = append(args, "--only-fixed")
	}

	cmd := exec.CommandContext(ctx, "grype", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, nil, fmt.Errorf("scan timed out after %v", s.Timeout)
		}
		// Grype returns non-zero when vulnerabilities are found; check if we got JSON output
		if stdout.Len() == 0 {
			return nil, nil, fmt.Errorf("grype failed: %s", stderr.String())
		}
	}

	var result Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	vulns, summary := parseMatches(result.Matches, s.MinSeverity)
	return vulns, summary, nil
}

func parseMatches(matches []Match, minSeverity string) ([]VulnItem, *Summary) {
	minLevel := severityLevel(minSeverity)
	summary := &Summary{}
	var vulns []VulnItem

	for _, m := range matches {
		level := severityLevel(m.Vulnerability.Severity)

		// Count all in summary
		switch m.Vulnerability.Severity {
		case "Critical":
			summary.Critical++
		case "High":
			summary.High++
		case "Medium":
			summary.Medium++
		case "Low":
			summary.Low++
		default:
			summary.Unknown++
		}

		// Only include vulns at or above min severity in the list
		if level < minLevel {
			continue
		}

		fixedIn := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixedIn = m.Vulnerability.Fix.Versions[0]
		}

		vulns = append(vulns, VulnItem{
			ID:       m.Vulnerability.ID,
			Severity: m.Vulnerability.Severity,
			Package:  m.Artifact.Name,
			Version:  m.Artifact.Version,
			FixedIn:  fixedIn,
		})
	}

	return vulns, summary
}

func severityLevel(s string) int {
	switch s {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}

// UpdateDB runs grype db update to refresh the vulnerability database.
func UpdateDB(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "grype", "db", "update")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("grype db update failed: %s", stderr.String())
	}
	return nil
}
