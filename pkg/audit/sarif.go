package audit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

const (
	// SARIFSchemaURI is the canonical OASIS SARIF 2.1.0 JSON schema URI.
	SARIFSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	// SARIFVersion is the OASIS SARIF specification version emitted by MCPGate.
	SARIFVersion = "2.1.0"
	// MCPGateVersion is the tool version stamped into SARIF tool metadata.
	MCPGateVersion = "1.0.0"
	// MCPGateInfoURI is the project homepage URI stamped into SARIF tool metadata.
	MCPGateInfoURI = "https://github.com/aloneangel45/mcpgate"
)

// SARIFLog is the top-level SARIF 2.1.0 log object ready for GitHub Code Scanning.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single MCPGate analysis or session run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool wraps the tool driver descriptor.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the MCPGate analyzer and all triggered rules.
type SARIFDriver struct {
	Name           string                     `json:"name"`
	Version        string                     `json:"version"`
	InformationURI string                     `json:"informationUri"`
	Rules          []SARIFReportingDescriptor `json:"rules"`
}

// SARIFReportingDescriptor defines metadata for a single security rule.
type SARIFReportingDescriptor struct {
	ID                   string                   `json:"id"`
	Name                 string                   `json:"name,omitempty"`
	ShortDescription     *SARIFMessage            `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMessage            `json:"fullDescription,omitempty"`
	Help                 *SARIFMessage            `json:"help,omitempty"`
	DefaultConfiguration *SARIFRuleConfiguration  `json:"defaultConfiguration,omitempty"`
	Properties           map[string]any           `json:"properties,omitempty"`
}

// SARIFRuleConfiguration sets a rule's default severity level.
type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

// SARIFResult represents a single finding or security event in SARIF format.
type SARIFResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    SARIFMessage     `json:"message"`
	Locations  []SARIFLocation  `json:"locations,omitempty"`
	Properties map[string]any   `json:"properties,omitempty"`
}

// SARIFMessage holds plain-text SARIF messages.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation locates a result in a source artifact.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation `json:"physicalLocation,omitempty"`
}

// SARIFPhysicalLocation identifies a file URI and optional line region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file URI (forward-slash normalized).
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion specifies a 1-based line number inside an artifact.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// BuildSARIFReport constructs a SARIF 2.1.0 log from a static AuditReport.
func BuildSARIFReport(report *AuditReport) SARIFLog {
	rulesMap := map[string]SARIFReportingDescriptor{}
	results := make([]SARIFResult, 0)

	if report != nil {
		results = make([]SARIFResult, 0, len(report.Findings))
		for _, f := range report.Findings {
			ruleID := strings.TrimSpace(f.RuleID)
			if ruleID == "" {
				ruleID = "MCPGATE-AUDIT"
			}
			level := severityToSARIFLevel(f.Severity)

			if _, exists := rulesMap[ruleID]; !exists {
				title := f.Title
				if title == "" {
					title = ruleID
				}
				rec := f.Recommendation
				if rec == "" {
					rec = "Review and harden MCP configuration according to OWASP MCP Top 10 guidance."
				}
				rulesMap[ruleID] = SARIFReportingDescriptor{
					ID:               ruleID,
					Name:             sanitizeRuleName(ruleID),
					ShortDescription: &SARIFMessage{Text: title},
					FullDescription:  &SARIFMessage{Text: title},
					Help:             &SARIFMessage{Text: rec},
					DefaultConfiguration: &SARIFRuleConfiguration{
						Level: level,
					},
					Properties: map[string]any{
						"tags":              []string{"security", "mcp", "owasp-mcp", f.Category},
						"security-severity": severityToSecurityScore(f.Severity),
					},
				}
			}

			res := SARIFResult{
				RuleID:  ruleID,
				Level:   level,
				Message: SARIFMessage{Text: f.Message},
				Properties: map[string]any{
					"severity": string(f.Severity),
					"category": f.Category,
				},
			}
			if f.Server != "" {
				res.Properties["server"] = f.Server
			}
			if f.Evidence != "" {
				res.Properties["evidence"] = f.Evidence
			}

			uri := normalizeArtifactURI(f.File)
			if uri != "" {
				loc := SARIFLocation{
					PhysicalLocation: &SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: uri},
					},
				}
				if f.Line > 0 {
					loc.PhysicalLocation.Region = &SARIFRegion{StartLine: f.Line}
				}
				res.Locations = []SARIFLocation{loc}
			}

			results = append(results, res)
		}
	}

	return SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "MCPGate",
						Version:        MCPGateVersion,
						InformationURI: MCPGateInfoURI,
						Rules:          sortedRules(rulesMap),
					},
				},
				Results: results,
			},
		},
	}
}

// ExportSARIFReport serializes an AuditReport as formatted SARIF 2.1.0 JSON.
func ExportSARIFReport(report *AuditReport) ([]byte, error) {
	log := BuildSARIFReport(report)
	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal SARIF report: %w", err)
	}
	return append(out, '\n'), nil
}

// BuildSARIFEvents constructs a SARIF 2.1.0 log from runtime policy.SecurityEvent records.
func BuildSARIFEvents(events []policy.SecurityEvent) SARIFLog {
	rulesMap := map[string]SARIFReportingDescriptor{}
	results := make([]SARIFResult, 0, len(events))

	for _, ev := range events {
		ruleID := strings.TrimSpace(ev.RuleID)
		if ruleID == "" {
			ruleID = "MCPGATE-RUNTIME"
		}
		level := severityToSARIFLevel(ev.Severity)

		if _, exists := rulesMap[ruleID]; !exists {
			short := fmt.Sprintf("MCPGate %s rule (%s)", ev.Category, ruleID)
			if ev.Category == "" {
				short = fmt.Sprintf("MCPGate runtime rule (%s)", ruleID)
			}
			rulesMap[ruleID] = SARIFReportingDescriptor{
				ID:               ruleID,
				Name:             sanitizeRuleName(ruleID),
				ShortDescription: &SARIFMessage{Text: short},
				DefaultConfiguration: &SARIFRuleConfiguration{
					Level: level,
				},
				Properties: map[string]any{
					"tags":              []string{"security", "mcp", "runtime", ev.Category},
					"security-severity": severityToSecurityScore(ev.Severity),
				},
			}
		}

		msg := strings.TrimSpace(ev.Message)
		if msg == "" {
			msg = fmt.Sprintf("[%s] action=%s target=%s", ruleID, ev.Action, ev.Target)
		}

		props := map[string]any{
			"severity": string(ev.Severity),
			"category": ev.Category,
			"action":   ev.Action,
		}
		if !ev.Timestamp.IsZero() {
			props["timestamp"] = ev.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00")
		}
		if ev.SessionID != "" {
			props["session_id"] = ev.SessionID
		}
		if ev.Server != "" {
			props["server"] = ev.Server
		}
		if ev.Tool != "" {
			props["tool"] = ev.Tool
		}
		if ev.Target != "" {
			props["target"] = ev.Target
		}

		res := SARIFResult{
			RuleID:     ruleID,
			Level:      level,
			Message:    SARIFMessage{Text: msg},
			Properties: props,
		}

		uri := eventLocationURI(ev)
		if uri != "" {
			res.Locations = []SARIFLocation{
				{
					PhysicalLocation: &SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: uri},
					},
				},
			}
		}

		results = append(results, res)
	}

	return SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "MCPGate",
						Version:        MCPGateVersion,
						InformationURI: MCPGateInfoURI,
						Rules:          sortedRules(rulesMap),
					},
				},
				Results: results,
			},
		},
	}
}

// ExportSARIFEvents serializes runtime policy.SecurityEvent records as formatted SARIF 2.1.0 JSON.
func ExportSARIFEvents(events []policy.SecurityEvent) ([]byte, error) {
	log := BuildSARIFEvents(events)
	out, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal SARIF events: %w", err)
	}
	return append(out, '\n'), nil
}

func severityToSARIFLevel(sev policy.Severity) string {
	switch sev {
	case policy.SeverityCritical, policy.SeverityHigh:
		return "error"
	case policy.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func severityToSecurityScore(sev policy.Severity) string {
	switch sev {
	case policy.SeverityCritical:
		return "9.5"
	case policy.SeverityHigh:
		return "7.5"
	case policy.SeverityMedium:
		return "5.0"
	case policy.SeverityLow:
		return "2.5"
	default:
		return "1.0"
	}
}

func normalizeArtifactURI(rawPath string) string {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return ""
	}
	p = filepath.ToSlash(p)
	p = strings.ReplaceAll(p, "\\", "/")
	return p
}

func eventLocationURI(ev policy.SecurityEvent) string {
	if ev.Metadata != nil {
		if f := strings.TrimSpace(ev.Metadata["file"]); f != "" {
			return normalizeArtifactURI(f)
		}
	}
	if t := strings.TrimSpace(ev.Target); t != "" {
		return normalizeArtifactURI(t)
	}
	if s := strings.TrimSpace(ev.Server); s != "" {
		return "mcp-server/" + s
	}
	return "mcpgate/session"
}

func sanitizeRuleName(ruleID string) string {
	var b strings.Builder
	for _, r := range ruleID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "MCPGateRule"
	}
	return b.String()
}

func sortedRules(m map[string]SARIFReportingDescriptor) []SARIFReportingDescriptor {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]SARIFReportingDescriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, m[id])
	}
	return out
}
