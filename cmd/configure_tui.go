package cmd

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	configurePhaseIntro = iota
	configurePhaseRunning
	configurePhaseDone
	configurePhaseFailed
)

type configureSequenceStep struct {
	label string
	work  func(*configureReporter) error
}

type configureStepDoneMsg struct {
	index   int
	details []string
	err     error
}

type configureTickMsg time.Time

type configureTUI struct {
	steps       []configureSequenceStep
	completed   []configureStepResult
	activeIndex int
	phase       int
	introChars  int
	spinner     int
	width       int
	errText     string
}

func newConfigureTUI(steps []configureSequenceStep) configureTUI {
	return configureTUI{
		steps:       steps,
		phase:       configurePhaseIntro,
		activeIndex: -1,
		width:       72,
	}
}

func (m configureTUI) Init() tea.Cmd {
	return configureTick()
}

func configureTick() tea.Cmd {
	return tea.Tick(70*time.Millisecond, func(t time.Time) tea.Msg {
		return configureTickMsg(t)
	})
}

func (m configureTUI) runStep(index int) tea.Cmd {
	if index < 0 || index >= len(m.steps) {
		return nil
	}
	work := m.steps[index].work
	return func() tea.Msg {
		reporter := &configureReporter{}
		err := work(reporter)
		_, details := reporter.snapshot()
		return configureStepDoneMsg{
			index:   index,
			details: details,
			err:     err,
		}
	}
}

func (m configureTUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
		}
		return m, nil

	case configureTickMsg:
		m.spinner = (m.spinner + 1) % len(configureSpinnerFrames)

		if m.phase == configurePhaseIntro {
			if m.introChars < len(configureTagline) {
				m.introChars += 2
				if m.introChars > len(configureTagline) {
					m.introChars = len(configureTagline)
				}
				return m, configureTick()
			}
			m.phase = configurePhaseRunning
			m.activeIndex = 0
			return m, tea.Batch(configureTick(), m.runStep(0))
		}

		if m.phase == configurePhaseRunning {
			return m, configureTick()
		}
		return m, nil

	case configureStepDoneMsg:
		label := m.steps[msg.index].label
		result := configureStepResult{
			label:   label,
			status:  configureStepSuccess,
			details: msg.details,
		}
		if msg.err != nil {
			result.status = configureStepFailed
			if msg.err.Error() != "" {
				result.details = append(result.details, msg.err.Error())
			}
			m.completed = append(m.completed, result)
			m.phase = configurePhaseFailed
			m.errText = msg.err.Error()
			m.activeIndex = -1
			return m, tea.Quit
		}

		m.completed = append(m.completed, result)
		next := msg.index + 1
		if next >= len(m.steps) {
			m.phase = configurePhaseDone
			m.activeIndex = -1
			return m, tea.Quit
		}

		m.activeIndex = next
		return m, m.runStep(next)

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m configureTUI) View() string {
	panelWidth := m.panelWidth()
	sections := []string{
		m.renderBanner(panelWidth),
		"",
		renderConfigureChecklist(panelWidth, m.completed, m.activeLabel()),
	}
	if m.phase == configurePhaseFailed {
		sections = append(sections, "", m.renderErrorPanel(panelWidth))
	}
	return strings.Join(sections, "\n")
}

func (m configureTUI) activeLabel() string {
	if m.phase == configurePhaseRunning && m.activeIndex >= 0 && m.activeIndex < len(m.steps) {
		return fmt.Sprintf("%s %s", m.steps[m.activeIndex].label, configureSpinnerFrames[m.spinner])
	}
	return ""
}

func (m configureTUI) panelWidth() int {
	w := m.width - 4
	if w < 48 {
		w = 48
	}
	if w > 78 {
		w = 78
	}
	return w
}

func (m configureTUI) renderBanner(width int) string {
	tagline := configureTagline
	if m.introChars < len(configureTagline) {
		tagline = configureTagline[:m.introChars]
	}

	lines := []string{
		lipConfigureTeal().Bold(true).Render("FeatherWings"),
		"",
		lipConfigureMuted().Italic(true).Render(tagline),
	}
	if m.introChars >= len(configureTagline) {
		lines = append(lines, lipConfigureInk().Render("Configure · panel join flow"))
	}

	return lipConfigureFrame().
		Width(width).
		Align(lipgloss.Center).
		Render(lipgloss.JoinVertical(lipgloss.Center, lines...))
}

func (m configureTUI) renderErrorPanel(width int) string {
	rows := []string{
		lipConfigureErr().Bold(true).Render("Configure failed"),
		"",
		lipConfigureMuted().Render(m.errText),
	}
	return lipConfigureFrame().
		Width(width).
		BorderForeground(lipgloss.Color("196")).
		Render(strings.Join(rows, "\n"))
}

func runConfigureTUI(steps []configureSequenceStep) ([]configureStepResult, error) {
	m := newConfigureTUI(steps)
	finalModel, err := tea.NewProgram(m).Run()
	if err != nil {
		return nil, err
	}
	fm, ok := finalModel.(configureTUI)
	if !ok {
		return nil, nil
	}
	if fm.phase == configurePhaseFailed {
		if fm.errText != "" {
			return fm.completed, fmt.Errorf("%s", fm.errText)
		}
		return fm.completed, fmt.Errorf("configure failed")
	}
	return fm.completed, nil
}
