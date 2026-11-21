package audit

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

type htmlKPI struct {
	Label string
	Value string
	Sub   string
	Tone  string // neutral | good | warn | danger | accent
}

type htmlRow struct {
	RuleID     string
	Severity   string
	Category   string
	Badge      string // action (for events) or server/file (for audit)
	Primary    string // server/tool/target summary
	Message    string
	Timestamp  string
	Details    [][2]string
	SearchBlob string
}

type htmlDocument struct {
	Title          string
	Subtitle       string
	Mode           string
	GeneratedAt    string
	KPIs           []htmlKPI
	SeverityCounts map[string]int
	Categories     []string
	Rows           []htmlRow
}

// RenderAuditHTML generates a self-contained dark-mode interactive HTML report
// from a static OWASP MCP Top 10 AuditReport. Zero external URLs or CDNs are referenced.
func RenderAuditHTML(report *AuditReport) (string, error) {
	if report == nil {
		report = newAuditReport()
		finalizeReport(report)
	}

	genAt := report.GeneratedAt
	if genAt.IsZero() {
		genAt = time.Now().UTC()
	}

	sevCounts := map[string]int{
		"critical": report.CountsBySeverity[policy.SeverityCritical],
		"high":     report.CountsBySeverity[policy.SeverityHigh],
		"medium":   report.CountsBySeverity[policy.SeverityMedium],
		"low":      report.CountsBySeverity[policy.SeverityLow],
		"info":     report.CountsBySeverity[policy.SeverityInfo],
	}

	gradeTone := "good"
	switch report.Grade {
	case "C":
		gradeTone = "warn"
	case "D", "F":
		gradeTone = "danger"
	}

	critHigh := sevCounts["critical"] + sevCounts["high"]
	chTone := "good"
	if critHigh > 0 {
		chTone = "danger"
	}

	kpis := []htmlKPI{
		{
			Label: "Security Grade",
			Value: report.Grade,
			Sub:   fmt.Sprintf("Risk Score %d / 100", report.RiskScore),
			Tone:  gradeTone,
		},
		{
			Label: "Total Findings",
			Value: strconv.Itoa(len(report.Findings)),
			Sub:   "OWASP MCP Top 10 checks",
			Tone:  "accent",
		},
		{
			Label: "Critical / High",
			Value: strconv.Itoa(critHigh),
			Sub:   fmt.Sprintf("%d critical, %d high", sevCounts["critical"], sevCounts["high"]),
			Tone:  chTone,
		},
		{
			Label: "Attack Surface",
			Value: strconv.Itoa(report.ServersChecked),
			Sub:   fmt.Sprintf("%d config file(s) scanned", len(report.ScannedFiles)),
			Tone:  "neutral",
		},
	}

	catSet := map[string]bool{}
	rows := make([]htmlRow, 0, len(report.Findings))
	for _, f := range report.Findings {
		cat := strings.ToLower(strings.TrimSpace(f.Category))
		if cat == "" {
			cat = "general"
		}
		catSet[cat] = true

		sev := strings.ToLower(strings.TrimSpace(string(f.Severity)))
		if sev == "" {
			sev = "info"
		}

		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		primary := f.Server
		if primary == "" {
			primary = filepath.Base(f.File)
		}

		details := [][2]string{
			{"Title", f.Title},
			{"File Location", loc},
		}
		if f.Server != "" {
			details = append(details, [2]string{"MCP Server", f.Server})
		}
		if f.Evidence != "" {
			details = append(details, [2]string{"Redacted Evidence", f.Evidence})
		}
		if f.Recommendation != "" {
			details = append(details, [2]string{"Remediation", f.Recommendation})
		}

		blob := strings.ToLower(strings.Join([]string{
			f.RuleID, sev, cat, f.Title, f.Server, f.File, f.Evidence, f.Message, f.Recommendation,
		}, " "))

		rows = append(rows, htmlRow{
			RuleID:     f.RuleID,
			Severity:   sev,
			Category:   cat,
			Badge:      cat,
			Primary:    primary,
			Message:    f.Message,
			Details:    details,
			SearchBlob: blob,
		})
	}

	doc := htmlDocument{
		Title:          "MCPGate Security Audit Report",
		Subtitle:       "Static OWASP MCP Top 10 Configuration & Policy Assessment",
		Mode:           "STATIC AUDIT",
		GeneratedAt:    genAt.UTC().Format("2006-01-02 15:04:05 UTC"),
		KPIs:           kpis,
		SeverityCounts: sevCounts,
		Categories:     sortedSetKeys(catSet),
		Rows:           rows,
	}
	return renderHTMLDocument(doc), nil
}

// RenderEventsHTML generates a self-contained dark-mode interactive HTML report
// from live runtime policy.SecurityEvent records (e.g. `mcpgate inspect --html`).
func RenderEventsHTML(events []policy.SecurityEvent, title string) (string, error) {
	if strings.TrimSpace(title) == "" {
		title = "MCPGate Runtime Security Session Report"
	}

	summary := Summarize(events)
	sevCounts := map[string]int{
		"critical": summary.BySeverity[policy.SeverityCritical],
		"high":     summary.BySeverity[policy.SeverityHigh],
		"medium":   summary.BySeverity[policy.SeverityMedium],
		"low":      summary.BySeverity[policy.SeverityLow],
		"info":     summary.BySeverity[policy.SeverityInfo],
	}

	blockedCount := summary.ByAction["blocked"] + summary.ByAction["block"] + summary.ByAction["denied"] + summary.ByAction["deny"]
	quarantinedCount := summary.ByAction["quarantined"] + summary.ByAction["quarantine"]
	dlpCount := summary.ByCategory["dlp"] + summary.ByAction["redacted"] + summary.ByAction["redact"]
	if summary.ByCategory["dlp"] > 0 && summary.ByAction["redacted"] > 0 {
		// Avoid double counting if DLP events also carry action=redacted; count unique DLP/redacted events.
		dlpCount = 0
		for _, ev := range events {
			if strings.EqualFold(ev.Category, "dlp") || strings.EqualFold(ev.Action, "redacted") || strings.EqualFold(ev.Action, "redact") {
				dlpCount++
			}
		}
	}

	blockTone := "good"
	if blockedCount > 0 {
		blockTone = "danger"
	}
	quarTone := "good"
	if quarantinedCount > 0 {
		quarTone = "warn"
	}
	dlpTone := "good"
	if dlpCount > 0 {
		dlpTone = "danger"
	}

	kpis := []htmlKPI{
		{
			Label: "Total Events",
			Value: strconv.Itoa(summary.TotalEvents),
			Sub:   fmt.Sprintf("%d unique rule(s) triggered", len(summary.ByRuleID)),
			Tone:  "accent",
		},
		{
			Label: "Blocked / Denied",
			Value: strconv.Itoa(blockedCount),
			Sub:   "Enforced zero-trust blocks",
			Tone:  blockTone,
		},
		{
			Label: "Quarantined",
			Value: strconv.Itoa(quarantinedCount),
			Sub:   "Poisoned / rug-pull tools isolated",
			Tone:  quarTone,
		},
		{
			Label: "DLP / Redactions",
			Value: strconv.Itoa(dlpCount),
			Sub:   "Secret exfiltration intercepts",
			Tone:  dlpTone,
		},
	}

	catSet := map[string]bool{}
	rows := make([]htmlRow, 0, len(events))
	for _, ev := range events {
		cat := strings.ToLower(strings.TrimSpace(ev.Category))
		if cat == "" {
			cat = "runtime"
		}
		catSet[cat] = true

		sev := strings.ToLower(strings.TrimSpace(string(ev.Severity)))
		if sev == "" {
			sev = "info"
		}

		primary := ev.Tool
		if primary == "" {
			primary = ev.Target
		}
		if primary == "" {
			primary = ev.Server
		}
		if primary == "" {
			primary = "-"
		}

		ts := ""
		if !ev.Timestamp.IsZero() {
			ts = ev.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
		}

		details := make([][2]string, 0, 8)
		if ts != "" {
			details = append(details, [2]string{"Timestamp", ts})
		}
		if ev.SessionID != "" {
			details = append(details, [2]string{"Session ID", ev.SessionID})
		}
		if ev.Action != "" {
			details = append(details, [2]string{"Action", ev.Action})
		}
		if ev.Server != "" {
			details = append(details, [2]string{"MCP Server", ev.Server})
		}
		if ev.Tool != "" {
			details = append(details, [2]string{"Tool", ev.Tool})
		}
		if ev.Target != "" {
			details = append(details, [2]string{"Target", ev.Target})
		}
		if len(ev.Metadata) > 0 {
			mkeys := make([]string, 0, len(ev.Metadata))
			for k := range ev.Metadata {
				mkeys = append(mkeys, k)
			}
			sort.Strings(mkeys)
			for _, k := range mkeys {
				details = append(details, [2]string{"meta." + k, ev.Metadata[k]})
			}
		}

		blobParts := []string{
			ev.RuleID, sev, cat, ev.Action, ev.SessionID, ev.Server, ev.Tool, ev.Target, ev.Message,
		}
		for k, v := range ev.Metadata {
			blobParts = append(blobParts, k, v)
		}

		rows = append(rows, htmlRow{
			RuleID:     ev.RuleID,
			Severity:   sev,
			Category:   cat,
			Badge:      ev.Action,
			Primary:    primary,
			Message:    ev.Message,
			Timestamp:  ts,
			Details:    details,
			SearchBlob: strings.ToLower(strings.Join(blobParts, " ")),
		})
	}

	doc := htmlDocument{
		Title:          title,
		Subtitle:       "Live Runtime Zero-Trust Firewall & DLP Event Telemetry",
		Mode:           "LIVE TELEMETRY",
		GeneratedAt:    time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		KPIs:           kpis,
		SeverityCounts: sevCounts,
		Categories:     sortedSetKeys(catSet),
		Rows:           rows,
	}
	return renderHTMLDocument(doc), nil
}

// WriteAuditHTML renders an AuditReport to HTML and writes it atomically to path.
func WriteAuditHTML(path string, report *AuditReport) error {
	content, err := RenderAuditHTML(report)
	if err != nil {
		return err
	}
	return writeReportFile(path, []byte(content))
}

// WriteEventsHTML renders SecurityEvents to HTML and writes it atomically to path.
func WriteEventsHTML(path string, events []policy.SecurityEvent, title string) error {
	content, err := RenderEventsHTML(events, title)
	if err != nil {
		return err
	}
	return writeReportFile(path, []byte(content))
}

func writeReportFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create report dir %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write HTML report %q: %w", path, err)
	}
	return nil
}

func renderHTMLDocument(doc htmlDocument) string {
	var b strings.Builder
	b.Grow(16 * 1024)

	esc := html.EscapeString

	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"UTF-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	b.WriteString("<title>" + esc(doc.Title) + "</title>\n")
	b.WriteString("<style>\n")
	b.WriteString(reportCSS)
	b.WriteString("\n</style>\n</head>\n<body>\n")

	b.WriteString("<div class=\"container\">\n")

	// Header
	b.WriteString("<header class=\"hero\">\n")
	b.WriteString("  <div class=\"hero-top\">\n")
	b.WriteString("    <div class=\"brand\"><span class=\"dot\"></span><span>MCPGATE</span><span class=\"mode-pill\">" + esc(doc.Mode) + "</span></div>\n")
	b.WriteString("    <div class=\"timestamp\">Generated " + esc(doc.GeneratedAt) + "</div>\n")
	b.WriteString("  </div>\n")
	b.WriteString("  <h1>" + esc(doc.Title) + "</h1>\n")
	b.WriteString("  <p class=\"subtitle\">" + esc(doc.Subtitle) + "</p>\n")
	b.WriteString("</header>\n")

	// KPI Grid
	b.WriteString("<section class=\"kpi-grid\">\n")
	for _, k := range doc.KPIs {
		b.WriteString("  <div class=\"kpi tone-" + esc(k.Tone) + "\">\n")
		b.WriteString("    <div class=\"kpi-label\">" + esc(k.Label) + "</div>\n")
		b.WriteString("    <div class=\"kpi-value\">" + esc(k.Value) + "</div>\n")
		b.WriteString("    <div class=\"kpi-sub\">" + esc(k.Sub) + "</div>\n")
		b.WriteString("  </div>\n")
	}
	b.WriteString("</section>\n")

	// Severity Distribution Bar
	total := len(doc.Rows)
	b.WriteString("<section class=\"panel\">\n")
	b.WriteString("  <div class=\"panel-head\"><h2>Severity Distribution</h2><span id=\"visible-count\" class=\"muted\">Showing " + strconv.Itoa(total) + " of " + strconv.Itoa(total) + "</span></div>\n")
	b.WriteString("  <div class=\"sev-bar\">\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		cnt := doc.SeverityCounts[sev]
		if cnt > 0 && total > 0 {
			pct := float64(cnt) * 100.0 / float64(total)
			fmt.Fprintf(&b, "    <div class=\"sev-seg sev-%s\" style=\"width:%.2f%%\" title=\"%s: %d\"></div>\n",
				esc(sev), pct, esc(strings.ToUpper(sev)), cnt)
		}
	}
	b.WriteString("  </div>\n")

	// Filter Controls
	b.WriteString("  <div class=\"controls\">\n")
	b.WriteString("    <div class=\"pill-group\" role=\"group\" aria-label=\"Severity filter\">\n")
	b.WriteString("      <button type=\"button\" class=\"pill active\" data-sev-filter=\"all\">All (" + strconv.Itoa(total) + ")</button>\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		cnt := doc.SeverityCounts[sev]
		b.WriteString("      <button type=\"button\" class=\"pill pill-" + esc(sev) + "\" data-sev-filter=\"" + esc(sev) + "\">" + esc(strings.ToUpper(sev)) + " (" + strconv.Itoa(cnt) + ")</button>\n")
	}
	b.WriteString("    </div>\n")

	if len(doc.Categories) > 0 {
		b.WriteString("    <div class=\"pill-group\" role=\"group\" aria-label=\"Category filter\">\n")
		b.WriteString("      <button type=\"button\" class=\"pill active\" data-cat-filter=\"all\">All Categories</button>\n")
		for _, cat := range doc.Categories {
			b.WriteString("      <button type=\"button\" class=\"pill\" data-cat-filter=\"" + esc(cat) + "\">" + esc(cat) + "</button>\n")
		}
		b.WriteString("    </div>\n")
	}

	b.WriteString("    <div class=\"search-wrap\">\n")
	b.WriteString("      <input id=\"search-box\" type=\"search\" placeholder=\"Search rule ID, server, tool, target, message...\" autocomplete=\"off\">\n")
	b.WriteString("    </div>\n")
	b.WriteString("  </div>\n")
	b.WriteString("</section>\n")

	// Findings / Events Table
	b.WriteString("<section class=\"panel\">\n")
	if len(doc.Rows) == 0 {
		b.WriteString("  <div class=\"empty-state\">No security findings or events recorded. Zero-trust posture is clean.</div>\n")
	} else {
		b.WriteString("  <div class=\"table-wrap\">\n")
		b.WriteString("    <table class=\"findings-table\">\n")
		b.WriteString("      <thead><tr><th>Severity</th><th>Rule ID</th><th>Category</th><th>Target / Server</th><th>Summary</th><th></th></tr></thead>\n")
		b.WriteString("      <tbody id=\"report-rows\">\n")
		for idx, r := range doc.Rows {
			rowID := fmt.Sprintf("detail-%d", idx)
			b.WriteString("        <tr class=\"data-row\" data-severity=\"" + esc(r.Severity) + "\" data-category=\"" + esc(r.Category) + "\" data-search=\"" + esc(r.SearchBlob) + "\" data-target=\"" + esc(rowID) + "\">\n")
			b.WriteString("          <td><span class=\"badge sev-" + esc(r.Severity) + "\">" + esc(strings.ToUpper(r.Severity)) + "</span></td>\n")
			b.WriteString("          <td class=\"mono\">" + esc(r.RuleID) + "</td>\n")
			b.WriteString("          <td><span class=\"cat-tag\">" + esc(r.Badge) + "</span></td>\n")
			b.WriteString("          <td class=\"mono\">" + esc(r.Primary) + "</td>\n")
			b.WriteString("          <td class=\"msg-cell\">" + esc(r.Message) + "</td>\n")
			b.WriteString("          <td class=\"expand-cell\"><button type=\"button\" class=\"expand-btn\" aria-expanded=\"false\">Details</button></td>\n")
			b.WriteString("        </tr>\n")

			b.WriteString("        <tr id=\"" + esc(rowID) + "\" class=\"detail-row hidden\" data-parent=\"" + esc(rowID) + "\">\n")
			b.WriteString("          <td colspan=\"6\">\n")
			b.WriteString("            <div class=\"detail-box\">\n")
			for _, kv := range r.Details {
				if strings.TrimSpace(kv[1]) == "" {
					continue
				}
				b.WriteString("              <div class=\"detail-item\"><span class=\"detail-key\">" + esc(kv[0]) + "</span><span class=\"detail-val mono\">" + esc(kv[1]) + "</span></div>\n")
			}
			b.WriteString("            </div>\n")
			b.WriteString("          </td>\n")
			b.WriteString("        </tr>\n")
		}
		b.WriteString("      </tbody>\n")
		b.WriteString("    </table>\n")
		b.WriteString("    <div id=\"no-match\" class=\"empty-state hidden\">No records match the active filter criteria.</div>\n")
		b.WriteString("  </div>\n")
	}
	b.WriteString("</section>\n")

	b.WriteString("<footer class=\"footer\">Generated offline by MCPGate v" + esc(MCPGateVersion) + " &middot; Self-contained report (zero external dependencies)</footer>\n")
	b.WriteString("</div>\n")

	b.WriteString("<script>\n")
	b.WriteString(reportJS)
	b.WriteString("\n</script>\n</body>\n</html>\n")
	return b.String()
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

const reportCSS = `:root {
  --bg: #080b12;
  --surface: #101624;
  --surface-2: #161f33;
  --border: #24304a;
  --text: #e6edf7;
  --muted: #8b9bb8;
  --accent: #38bdf8;
  --crit: #ef4444;
  --high: #f97316;
  --med: #eab308;
  --low: #3b82f6;
  --info: #64748b;
  --good: #22c55e;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: radial-gradient(circle at top right, #121c33 0%, var(--bg) 52%);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  line-height: 1.5;
  min-height: 100vh;
}
.container { max-width: 1240px; margin: 0 auto; padding: 28px 20px 48px; }
.hero {
  background: linear-gradient(135deg, #111827 0%, #0f172a 60%, #0c1f30 100%);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px 28px;
  margin-bottom: 20px;
}
.hero-top { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: 0.12em; font-size: 13px; color: var(--accent); }
.dot { width: 9px; height: 9px; border-radius: 999px; background: var(--accent); box-shadow: 0 0 12px var(--accent); }
.mode-pill { font-size: 11px; letter-spacing: 0.08em; padding: 3px 9px; border-radius: 999px; background: rgba(56,189,248,0.14); border: 1px solid rgba(56,189,248,0.35); color: #bae6fd; }
.timestamp { font-size: 12px; color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.hero h1 { margin: 4px 0 6px; font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
.subtitle { margin: 0; color: var(--muted); font-size: 14px; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 20px; }
.kpi {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  position: relative;
  overflow: hidden;
}
.kpi::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--border); }
.kpi.tone-good::before { background: var(--good); }
.kpi.tone-warn::before { background: var(--med); }
.kpi.tone-danger::before { background: var(--crit); }
.kpi.tone-accent::before { background: var(--accent); }
.kpi-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
.kpi-value { font-size: 32px; font-weight: 800; margin: 6px 0 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.kpi.tone-good .kpi-value { color: #4ade80; }
.kpi.tone-warn .kpi-value { color: #facc15; }
.kpi.tone-danger .kpi-value { color: #f87171; }
.kpi.tone-accent .kpi-value { color: var(--accent); }
.kpi-sub { font-size: 12px; color: var(--muted); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; margin-bottom: 18px; }
.panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.panel-head h2 { margin: 0; font-size: 15px; font-weight: 600; letter-spacing: 0.02em; }
.muted { color: var(--muted); font-size: 13px; }
.sev-bar { display: flex; height: 10px; border-radius: 999px; overflow: hidden; background: var(--surface-2); margin-bottom: 16px; }
.sev-seg { height: 100%; }
.controls { display: flex; flex-direction: column; gap: 12px; }
.pill-group { display: flex; flex-wrap: wrap; gap: 8px; }
.pill {
  background: var(--surface-2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 6px 12px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: border-color 0.15s, background 0.15s;
}
.pill:hover { border-color: var(--accent); }
.pill.active { background: rgba(56,189,248,0.18); border-color: var(--accent); color: #e0f2fe; }
.search-wrap input {
  width: 100%;
  background: #0b101b;
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 10px 14px;
  font-size: 14px;
  outline: none;
}
.search-wrap input:focus { border-color: var(--accent); }
.table-wrap { overflow-x: auto; }
.findings-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.findings-table th {
  text-align: left;
  padding: 10px 12px;
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  border-bottom: 1px solid var(--border);
}
.findings-table td { padding: 12px; border-bottom: 1px solid rgba(36,48,74,0.65); vertical-align: top; }
.data-row { cursor: pointer; transition: background 0.12s; }
.data-row:hover { background: rgba(56,189,248,0.06); }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
.msg-cell { max-width: 520px; word-break: break-word; }
.badge { display: inline-block; padding: 3px 9px; border-radius: 6px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; }
.sev-critical { background: rgba(239,68,68,0.18); color: #fca5a5; border: 1px solid rgba(239,68,68,0.45); }
.sev-high { background: rgba(249,115,22,0.18); color: #fdba74; border: 1px solid rgba(249,115,22,0.45); }
.sev-medium { background: rgba(234,179,8,0.16); color: #fde047; border: 1px solid rgba(234,179,8,0.4); }
.sev-low { background: rgba(59,130,246,0.18); color: #93c5fd; border: 1px solid rgba(59,130,246,0.45); }
.sev-info { background: rgba(100,116,139,0.2); color: #cbd5e1; border: 1px solid rgba(100,116,139,0.4); }
.sev-bar .sev-critical { background: var(--crit); border: none; }
.sev-bar .sev-high { background: var(--high); border: none; }
.sev-bar .sev-medium { background: var(--med); border: none; }
.sev-bar .sev-low { background: var(--low); border: none; }
.sev-bar .sev-info { background: var(--info); border: none; }
.cat-tag { display: inline-block; padding: 2px 8px; border-radius: 6px; background: var(--surface-2); border: 1px solid var(--border); color: #cbd5e1; font-size: 11px; }
.expand-cell { text-align: right; white-space: nowrap; }
.expand-btn {
  background: transparent;
  color: var(--accent);
  border: 1px solid rgba(56,189,248,0.35);
  border-radius: 6px;
  padding: 4px 9px;
  font-size: 11px;
  cursor: pointer;
}
.expand-btn:hover { background: rgba(56,189,248,0.12); }
.detail-row td { background: #0c121f; padding: 14px 18px; }
.detail-box { display: grid; gap: 8px; }
.detail-item { display: grid; grid-template-columns: 165px 1fr; gap: 12px; align-items: start; }
.detail-key { color: var(--muted); font-size: 12px; font-weight: 600; }
.detail-val { color: var(--text); word-break: break-word; }
.empty-state { text-align: center; padding: 36px 16px; color: var(--muted); font-size: 14px; }
.hidden { display: none !important; }
.footer { text-align: center; color: var(--muted); font-size: 12px; margin-top: 22px; }
@media (max-width: 720px) {
  .detail-item { grid-template-columns: 1fr; gap: 2px; }
}`

const reportJS = `(function() {
  var activeSev = "all";
  var activeCat = "all";
  var searchQuery = "";

  var rows = Array.prototype.slice.call(document.querySelectorAll("tr.data-row"));
  var sevBtns = Array.prototype.slice.call(document.querySelectorAll("[data-sev-filter]"));
  var catBtns = Array.prototype.slice.call(document.querySelectorAll("[data-cat-filter]"));
  var searchBox = document.getElementById("search-box");
  var visibleCount = document.getElementById("visible-count");
  var noMatch = document.getElementById("no-match");

  function applyFilters() {
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {
      var row = rows[i];
      var sev = row.getAttribute("data-severity") || "";
      var cat = row.getAttribute("data-category") || "";
      var blob = row.getAttribute("data-search") || "";
      var detailId = row.getAttribute("data-target");
      var detailRow = detailId ? document.getElementById(detailId) : null;

      var sevOK = (activeSev === "all" || sev === activeSev);
      var catOK = (activeCat === "all" || cat === activeCat);
      var qOK = (!searchQuery || blob.indexOf(searchQuery) !== -1);

      if (sevOK && catOK && qOK) {
        row.classList.remove("hidden");
        shown++;
      } else {
        row.classList.add("hidden");
        if (detailRow) {
          detailRow.classList.add("hidden");
          var btn = row.querySelector(".expand-btn");
          if (btn) {
            btn.setAttribute("aria-expanded", "false");
            btn.textContent = "Details";
          }
        }
      }
    }
    if (visibleCount) {
      visibleCount.textContent = "Showing " + shown + " of " + rows.length;
    }
    if (noMatch) {
      if (rows.length > 0 && shown === 0) {
        noMatch.classList.remove("hidden");
      } else {
        noMatch.classList.add("hidden");
      }
    }
  }

  for (var s = 0; s < sevBtns.length; s++) {
    sevBtns[s].addEventListener("click", function(e) {
      activeSev = e.currentTarget.getAttribute("data-sev-filter") || "all";
      for (var k = 0; k < sevBtns.length; k++) {
        sevBtns[k].classList.toggle("active", sevBtns[k] === e.currentTarget);
      }
      applyFilters();
    });
  }

  for (var c = 0; c < catBtns.length; c++) {
    catBtns[c].addEventListener("click", function(e) {
      activeCat = e.currentTarget.getAttribute("data-cat-filter") || "all";
      for (var k = 0; k < catBtns.length; k++) {
        catBtns[k].classList.toggle("active", catBtns[k] === e.currentTarget);
      }
      applyFilters();
    });
  }

  if (searchBox) {
    searchBox.addEventListener("input", function(e) {
      searchQuery = (e.currentTarget.value || "").trim().toLowerCase();
      applyFilters();
    });
  }

  for (var r = 0; r < rows.length; r++) {
    rows[r].addEventListener("click", function(e) {
      var row = e.currentTarget;
      var detailId = row.getAttribute("data-target");
      if (!detailId) return;
      var detailRow = document.getElementById(detailId);
      if (!detailRow) return;
      var isHidden = detailRow.classList.toggle("hidden");
      var btn = row.querySelector(".expand-btn");
      if (btn) {
        btn.setAttribute("aria-expanded", isHidden ? "false" : "true");
        btn.textContent = isHidden ? "Details" : "Hide";
      }
    });
  }
})();`
