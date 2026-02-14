package monitor

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
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
	context     string
	snap        store.Snapshot
	allFindings []store.CertFinding // full sorted set
	findings    []store.CertFinding // current view (may be filtered)
	table       table.Model
	width       int
	height      int
	quitting    bool
	searching   bool
	searchInput textinput.Model
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

	ti := textinput.New()
	ti.Placeholder = "type to filter..."
	ti.CharLimit = 64

	return &Model{
		snap:        snap,
		table:       t,
		allFindings: findings,
		findings:    findings,
		context:     kubeContext,
		width:       80,
		height:      24,
		searchInput: ti,
	}
}

// Init satisfies tea.Model.
func (m *Model) Init() tea.Cmd {
	return nil
}

// Update handles key events.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.searching {
		return m.updateSearch(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			if m.searchInput.Value() != "" {
				m.searchInput.SetValue("")
				m.applyFilter()
				return m, nil
			}
			m.quitting = true
			return m, tea.Quit
		case "/":
			m.searching = true
			return m, m.searchInput.Focus()
		case "g":
			m.table.GotoTop()
			return m, nil
		case "G":
			m.table.GotoBottom()
			return m, nil
		case "1", "2", "3", "4", "5", "6", "7", "8", "9":
			n := int(msg.String()[0] - '0')
			if n <= len(m.findings) {
				m.table.SetCursor(n - 1)
			}
			return m, nil
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

func (m *Model) updateSearch(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			m.searching = false
			m.searchInput.Blur()
			return m, nil
		case "esc":
			m.searching = false
			m.searchInput.SetValue("")
			m.searchInput.Blur()
			m.applyFilter()
			return m, nil
		case "ctrl+c":
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
	m.searchInput, cmd = m.searchInput.Update(msg)
	m.applyFilter()
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

	totalStr := fmt.Sprintf("Total: %d", len(m.findings))
	if len(m.findings) != len(m.allFindings) {
		totalStr = fmt.Sprintf("Showing: %d/%d", len(m.findings), len(m.allFindings))
	}

	counts := headerStyle.Render(fmt.Sprintf(
		"%s  %s  %s  %s",
		critStyle.Render(fmt.Sprintf("Critical: %d", crit)),
		warnStyle.Render(fmt.Sprintf("Warn: %d", warn)),
		fmt.Sprintf("Info: %d", info),
		totalStr,
	))

	return title + "\n" + counts
}

func (m *Model) detailView() string {
	if len(m.findings) == 0 {
		if m.searchInput.Value() != "" {
			return detailStyle.Render(dimStyle.Render("No matches."))
		}
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
	if m.searching {
		return " /" + m.searchInput.View()
	}
	help := " q quit · ↑↓/jk navigate · g/G top/bottom · 1-9 jump · / search"
	if m.searchInput.Value() != "" {
		help += " · esc clear"
	}
	return dimStyle.Render(help)
}

func (m *Model) tableHeight() int {
	// Reserve space for header, table chrome, separator, detail panel, and footer.
	reserved := 14
	h := m.height - reserved
	if h < 3 {
		h = 3
	}
	return h
}

func (m *Model) applyFilter() {
	query := strings.ToLower(m.searchInput.Value())
	if query == "" {
		m.findings = m.allFindings
	} else {
		var filtered []store.CertFinding
		for i := range m.allFindings {
			f := &m.allFindings[i]
			hay := strings.ToLower(f.Name + " " + f.Namespace + " " + string(f.Source) + " " + f.Target + " " + f.ProbeErr)
			if strings.Contains(hay, query) {
				filtered = append(filtered, m.allFindings[i])
			}
		}
		m.findings = filtered
	}
	m.rebuildRows()
}

func (m *Model) rebuildRows() {
	rows := make([]table.Row, len(m.findings))
	for i := range m.findings {
		rows[i] = findingToRow(&m.findings[i], m.snap.At)
	}
	m.table.SetRows(rows)
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

// findingToRow converts a finding to a table row with plain text (no ANSI).
// Embedding ANSI in cells causes the table to miscalculate column widths
// and truncate escape sequences, bleeding color into adjacent cells/rows.
func findingToRow(f *store.CertFinding, now time.Time) table.Row {
	var sev string
	switch f.Severity {
	case store.SeverityCritical:
		sev = "CRIT"
	case store.SeverityWarn:
		sev = "WARN"
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

// FormatExpiresIn returns a human-readable relative time (plain text).
func FormatExpiresIn(notAfter, now time.Time) string {
	d := notAfter.Sub(now)
	if d < 0 {
		return "EXPIRED"
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
