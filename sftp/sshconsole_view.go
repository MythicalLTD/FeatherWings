package sftp

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/system"
)

func sshConfiguredAppName() string {
	n := strings.TrimSpace(config.Get().AppName)
	if n == "" {
		return "Panel"
	}
	return n
}

// Terminal width for framed panels (ASCII borders via lipgloss.NormalBorder).
const sshUIViewWidth = 68

// Lipgloss styles: colors work in 256-color and truecolor terminals (PuTTY, Windows Terminal, xterm).
var (
	lipFrame  = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("39")).Padding(0, 1)
	lipTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51"))
	// Bold only (no fixed 256-color white): bright white breaks some PuTTY modes and can clip text.
	lipStrong = lipgloss.NewStyle().Bold(true)
	lipKey    = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	lipMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	lipOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	lipWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	lipErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
)

func viewStateLine(state string) string {
	var tag string
	switch state {
	case environment.ProcessRunningState:
		tag = lipOK.Render("[RUN]")
	case environment.ProcessStartingState, environment.ProcessStoppingState:
		tag = lipWarn.Render("[BUSY]")
	case environment.ProcessOfflineState:
		tag = lipMuted.Render("[OFF]")
	default:
		tag = lipMuted.Render("[ ? ]")
	}
	return tag + "  " + lipStrong.Render(state)
}

// renderSSHWelcomeScreen builds the ASCII-framed header and session info (no emoji / no Unicode decor).
func renderSSHWelcomeScreen(sshUser, sidShort, sidFull, state string) string {
	app := sshConfiguredAppName()
	head := lipTitle.Render(app) + lipMuted.Render("  |  ") + lipStrong.Render("Game console")
	sub := lipMuted.Render(fmt.Sprintf("Same stdin/stdout as your game process, like the %s web console.", app))

	box := lipFrame.Width(sshUIViewWidth).Render(
		lipgloss.JoinVertical(lipgloss.Left, head, sub),
	)

	kUser := lipMuted.Render("SSH user")
	kSrv := lipMuted.Render("Server id")
	vUser := lipKey.Render(sshUser)
	vShort := lipKey.Render(sidShort)
	vFull := lipMuted.Render("(" + sidFull + ")")

	tip := lipMuted.Render("Tip: ") +
		lipKey.Render(".help") + lipMuted.Render("  ") +
		lipKey.Render(".featherwings ...") + lipMuted.Render("  ") +
		lipKey.Render(".fw ...")

	daemon := lipMuted.Render("> Daemon  ") +
		lipKey.Render("status") + lipMuted.Render("  ") +
		lipKey.Render("logs") + lipMuted.Render("  ") +
		lipKey.Render("start") + lipMuted.Render("  ") +
		lipKey.Render("stop") + lipMuted.Render("  ") +
		lipKey.Render("restart") + lipMuted.Render("  ") +
		lipKey.Render("kill")

	rule := lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4))

	stateRow := lipMuted.Render("State ") + viewStateLine(state)

	pad := func(styledLabel string) string {
		n := 12 - lipgloss.Width(styledLabel)
		if n < 2 {
			n = 2
		}
		return strings.Repeat(" ", n)
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		"",
		box,
		"",
		"  "+kUser+pad(kUser)+vUser,
		"  "+kSrv+pad(kSrv)+vShort+" "+vFull,
		"",
		"  "+tip,
		"",
		"  "+daemon,
		"",
		"  "+rule,
		"  "+stateRow,
		"  "+rule,
		"",
	)
	return body
}

func renderSSHLogPreamble(lineCount int) string {
	// Label on its own line avoids PuTTY/layout glues eating the start of a long styled line.
	return "  " + lipStrong.Render("Recent output") + "\n  " +
		lipMuted.Render(fmt.Sprintf("%d line(s) from the log buffer.", lineCount))
}

func renderSSHLogEmpty() string {
	return "  " + lipStrong.Render("Recent output") + "\n  " +
		lipMuted.Render("No process running yet — nothing to stream. Start with ") +
		lipKey.Render(sshConsoleMetaPrefix+" start") +
		lipMuted.Render(" or from the "+sshConfiguredAppName()+" panel.")
}

func renderSSHLogFooter() string {
	rule := lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4))
	return "  " + rule + "\n  " + lipMuted.Render("--- live log stream ---") + "\n"
}

func renderSSHReadLogError(err error) string {
	return lipErr.Render("[ERR]") + "  " + lipMuted.Render("Could not load recent output: "+err.Error())
}

func renderSSHAbout() string {
	app := sshConfiguredAppName()
	return lipgloss.JoinVertical(lipgloss.Left,
		"",
		"  "+lipStrong.Render(app+" / Wings")+"  "+lipMuted.Render("daemon "+system.Version),
		"  "+lipMuted.Render("SSH game console session."),
		"",
	)
}

func renderSSHHelp() string {
	app := sshConfiguredAppName()
	title := lipStrong.Render(app+" daemon helpers") + lipMuted.Render("  (prefix: "+sshConsoleMetaPrefix+" / "+sshConsoleShortPrefix+")")
	rule := lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4))

	row := func(cmd, desc string) string {
		pad := 14 - len(cmd)
		if pad < 2 {
			pad = 2
		}
		return "  " + lipKey.Render(cmd) + strings.Repeat(" ", pad) + lipMuted.Render(desc)
	}

	b := lipgloss.JoinVertical(lipgloss.Left,
		"",
		"  "+rule,
		"  "+title,
		"  "+rule,
		row("help", "This list"),
		row("exit", "Close this SSH session (also: .exit, .quit, .bye)"),
		row("status", "Print current process state"),
		row("logs", "Replay last log lines"),
		row("start", "Start server (after panel sync)"),
		row("stop", "Graceful stop"),
		row("restart", "Stop then start"),
		row("kill", "SIGKILL container"),
		row("clear", "Clear the terminal screen"),
		row("about", "App name and daemon version"),
		row("echo <text>", "Print text back"),
		"  "+rule,
		"  "+lipMuted.Render("Power actions use panel permissions unless ")+lipKey.Render("allow_console_shell"),
		"  "+lipMuted.Render("is true in the Wings daemon config."),
		"  "+rule,
		"",
	)
	return b
}

func renderSSHStatusPanel(state string) string {
	rule := lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4))
	return lipgloss.JoinVertical(lipgloss.Left,
		"",
		"  "+rule,
		"  "+lipStrong.Render("State")+"  "+viewStateLine(state),
		"  "+rule,
		"",
	)
}

func renderSSHScrollbackHeader(n int) string {
	rule := lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4))
	return "\n  " + rule + "\n  " + lipStrong.Render("Scrollback") + "  " + lipMuted.Render(fmt.Sprintf("%d lines", n)) + "\n  " + rule + "\n"
}

func viewOK(msg string) string  { return lipOK.Render("[OK]") + "  " + msg }
func viewWarn(msg string) string { return lipWarn.Render("[WARN]") + "  " + msg }
func viewErr(msg string) string  { return lipErr.Render("[ERR]") + "  " + msg }
func viewNote(msg string) string { return lipMuted.Render("[*]") + "  " + msg }
