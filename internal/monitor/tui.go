package monitor

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ppiankov/trustwatch/internal/store"
)

var (
	critStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))  // red
	warnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11")) // yellow
	dimStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))  // dim gray

	headerStyle    = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	detailStyle    = lipgloss.NewStyle().Padding(0, 1)
	separatorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// Model is the BubbleTea model for the now TUI.
type Model struct {
	context  string
	snap     store.Snapshot
	findings []store.CertFinding
	table    table.Model
	width    int
	height   int
	quitting bool
}

// NewModel creates a TUI model from a completed snapshot.
func NewModel(snap store.Snapshot, kubeContext string) *Model {
	findings := sortFindings(snap.Findings)

	cols := []table.Column{
		{Title: "SEV", Width: 8},
		{Title: "SOURCE", Width: 16},
		{Title: "WHERE", Width: 30},
		{Title: "EXPIRES", Width: 14},
		{Title: "ERROR", Width: 20},
	}

	rows := make([]table.Row, len(findings))
	for i := range findings {
		rows[i] = findingToRow(&findings[i], snap.At)
	}

	s := table.DefaultStyles()
	s.Header = s.Header.Bold(true).BorderBottom(true).
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240"))
	s.Selected = s.Selected.Bold(true).
		Foreground(lipgloss.Color("15")).
		Background(lipgloss.Color("57"))

	t := table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(s),
	)

	return &Model{
		snap:     snap,
		table:    t,
		findings: findings,
		context:  kubeContext,
		width:    80,
		height:   24,
	}
}

// Init satisfies tea.Model.
func (m *Model) Init() tea.Cmd {
	return nil
}

// Update handles key events.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.SetHeight(m.tableHeight())
		m.table.SetWidth(m.width)
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// View renders the full TUI.
func (m *Model) View() string {
	if m.quitting {
		return ""
	}

	var b strings.Builder
	b.WriteString(m.headerView())
	b.WriteByte('\n')
	b.WriteString(m.table.View())
	b.WriteByte('\n')
	b.WriteString(separatorStyle.Render(strings.Repeat("─", m.width)))
	b.WriteByte('\n')
	b.WriteString(m.detailView())
	b.WriteByte('\n')
	b.WriteString(m.footerView())
	return b.String()
}

func (m *Model) headerView() string {
	ctx := m.context
	if ctx == "" {
		ctx = "(default)"
	}

	var crit, warn, info int
	for i := range m.findings {
		switch m.findings[i].Severity {
		case store.SeverityCritical:
			crit++
		case store.SeverityWarn:
			warn++
		default:
			info++
		}
	}

	title := headerStyle.Render(fmt.Sprintf("trustwatch · %s · %s",
		ctx, m.snap.At.UTC().Format("2006-01-02 15:04 UTC")))

	counts := headerStyle.Render(fmt.Sprintf(
		"%s  %s  %s  Total: %d",
		critStyle.Render(fmt.Sprintf("Critical: %d", crit)),
		warnStyle.Render(fmt.Sprintf("Warn: %d", warn)),
		fmt.Sprintf("Info: %d", info),
		len(m.findings),
	))

	return title + "\n" + counts
}

func (m *Model) detailView() string {
	if len(m.findings) == 0 {
		return detailStyle.Render("No findings.")
	}

	idx := m.table.Cursor()
	if idx < 0 || idx >= len(m.findings) {
		return ""
	}

	f := &m.findings[idx]
	var lines []string

	if len(f.DNSNames) > 0 {
		lines = append(lines, fmt.Sprintf("SANs: %s", strings.Join(f.DNSNames, ", ")))
	}
	if f.Issuer != "" {
		lines = append(lines, fmt.Sprintf("Issuer: %s", f.Issuer))
	}
	if f.Subject != "" {
		lines = append(lines, fmt.Sprintf("Subject: %s", f.Subject))
	}
	if f.Serial != "" {
		lines = append(lines, fmt.Sprintf("Serial: %s", f.Serial))
	}
	if f.SNI != "" {
		lines = append(lines, fmt.Sprintf("SNI: %s", f.SNI))
	}
	if f.Notes != "" {
		lines = append(lines, fmt.Sprintf("Notes: %s", f.Notes))
	}
	if f.ProbeErr != "" {
		lines = append(lines, fmt.Sprintf("Error: %s", critStyle.Render(f.ProbeErr)))
	}

	if len(lines) == 0 {
		return detailStyle.Render(dimStyle.Render("(no details)"))
	}
	return detailStyle.Render(strings.Join(lines, "\n"))
}

func (m *Model) footerView() string {
	return dimStyle.Render(" q/esc quit · ↑↓ navigate")
}

func (m *Model) tableHeight() int {
	// header=3, detail=6, footer=1, padding=2
	reserved := 12
	h := m.height - reserved
	if h < 3 {
		h = 3
	}
	return h
}

// PlainText returns a non-interactive text representation for piped output.
func PlainText(snap store.Snapshot) string {
	findings := sortFindings(snap.Findings)
	if len(findings) == 0 {
		return "No findings."
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%-8s %-16s %-30s %-14s %s\n", "SEV", "SOURCE", "WHERE", "EXPIRES", "ERROR")
	fmt.Fprintf(&b, "%-8s %-16s %-30s %-14s %s\n", "---", "------", "-----", "-------", "-----")
	for i := range findings {
		row := findingToRow(&findings[i], snap.At)
		fmt.Fprintf(&b, "%-8s %-16s %-30s %-14s %s\n", row[0], row[1], row[2], row[3], row[4])
	}
	return b.String()
}

func findingToRow(f *store.CertFinding, now time.Time) table.Row {
	var sev string
	switch f.Severity {
	case store.SeverityCritical:
		sev = critStyle.Render("CRIT")
	case store.SeverityWarn:
		sev = warnStyle.Render("WARN")
	default:
		sev = "INFO"
	}

	where := f.Name
	if f.Namespace != "" {
		where = f.Namespace + "/" + f.Name
	}

	expires := ""
	if !f.NotAfter.IsZero() {
		expires = FormatExpiresIn(f.NotAfter, now)
	}

	probeErr := ""
	if f.ProbeErr != "" {
		probeErr = truncate(f.ProbeErr, 20)
	}

	return table.Row{sev, string(f.Source), where, expires, probeErr}
}

// FormatExpiresIn returns a human-readable relative time.
func FormatExpiresIn(notAfter, now time.Time) string {
	d := notAfter.Sub(now)
	if d < 0 {
		return critStyle.Render("EXPIRED")
	}

	days := int(math.Floor(d.Hours() / 24))
	hours := int(math.Floor(d.Hours())) % 24

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh", hours)
	default:
		mins := int(d.Minutes())
		return fmt.Sprintf("%dm", mins)
	}
}

// sortFindings returns a sorted copy: critical first, then warn, then info.
// Within the same severity, earlier expiry first.
func sortFindings(findings []store.CertFinding) []store.CertFinding {
	sorted := make([]store.CertFinding, len(findings))
	copy(sorted, findings)

	sevOrder := map[store.Severity]int{
		store.SeverityCritical: 0,
		store.SeverityWarn:     1,
		store.SeverityInfo:     2,
	}

	sort.SliceStable(sorted, func(i, j int) bool {
		si, sj := sevOrder[sorted[i].Severity], sevOrder[sorted[j].Severity]
		if si != sj {
			return si < sj
		}
		return sorted[i].NotAfter.Before(sorted[j].NotAfter)
	})

	return sorted
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
