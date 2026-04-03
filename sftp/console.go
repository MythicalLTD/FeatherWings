package sftp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"golang.org/x/crypto/ssh"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/environment/docker"
	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/system"
)

// Same permission keys as router/websocket.
const (
	permissionConsole            = "control.console"
	permissionSendPowerStart     = "control.start"
	permissionSendPowerStop      = "control.stop"
	permissionSendPowerRestart   = "control.restart"
)

const sshConsoleMetaPrefix = ".featherwings"
const sshConsoleShortPrefix = ".fw"

// ErrSSHConsoleDisconnect is returned when the user runs a daemon quit command (e.g. .featherwings exit).
var ErrSSHConsoleDisconnect = errors.New("ssh console: disconnect requested")

// sshChannelOut serializes every Write to the SSH channel (log stream + echo + prompts).
// x/crypto/ssh channels are not safe for concurrent writes; without this, local echo breaks.
type sshChannelOut struct {
	ch ssh.Channel
	mu sync.Mutex
}

func (o *sshChannelOut) WriteRaw(p []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.ch.Write(p)
	return err
}

func (o *sshChannelOut) WriteLine(format string, args ...interface{}) error {
	s := format
	if len(args) > 0 {
		s = fmt.Sprintf(format, args...)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := fmt.Fprintf(o.ch, "%s\r\n", strings.TrimRight(s, "\r\n"))
	return err
}

func (o *sshChannelOut) WriteLineRaw(line string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := fmt.Fprintf(o.ch, "%s\r\n", line)
	return err
}

// WriteRenderedBlock writes lipgloss / ANSI output using CRLF line endings for SSH clients.
func (o *sshChannelOut) WriteRenderedBlock(s string) error {
	if s == "" {
		return nil
	}
	s = strings.TrimRight(s, "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n") + "\r\n"
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.ch.Write([]byte(s))
	return err
}

func outOK(out *sshChannelOut, format string, args ...interface{}) {
	_ = out.WriteRenderedBlock(viewOK(fmt.Sprintf(format, args...)))
}

func outWarn(out *sshChannelOut, format string, args ...interface{}) {
	_ = out.WriteRenderedBlock(viewWarn(fmt.Sprintf(format, args...)))
}

func outErr(out *sshChannelOut, format string, args ...interface{}) {
	_ = out.WriteRenderedBlock(viewErr(fmt.Sprintf(format, args...)))
}

func outNote(out *sshChannelOut, format string, args ...interface{}) {
	_ = out.WriteRenderedBlock(viewNote(fmt.Sprintf(format, args...)))
}

func outRule(out *sshChannelOut) {
	_ = out.WriteRenderedBlock(lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4)))
}

func normalizeSSHConsoleInput(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.EqualFold(cmd, ".help") {
		return sshConsoleMetaPrefix + " help"
	}
	if strings.EqualFold(cmd, sshConsoleMetaPrefix) {
		return sshConsoleMetaPrefix + " help"
	}
	if strings.EqualFold(cmd, ".exit") || strings.EqualFold(cmd, ".quit") || strings.EqualFold(cmd, ".bye") || strings.EqualFold(cmd, ".disconnect") {
		return sshConsoleMetaPrefix + " exit"
	}
	if len(cmd) >= 3 && strings.EqualFold(cmd[:3], sshConsoleShortPrefix) {
		tail := strings.TrimSpace(cmd[3:])
		if tail == "" {
			tail = "help"
		}
		return sshConsoleMetaPrefix + " " + tail
	}
	return cmd
}

func hasPermission(perms []string, want string) bool {
	for _, p := range perms {
		if strings.TrimSpace(p) == want {
			return true
		}
	}
	return false
}

func splitPermissions(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func isSftpSubsystem(payload []byte) bool {
	// SSH string: uint32 length + name (see golang.org/x/crypto/ssh)
	if len(payload) < 4 {
		return false
	}
	return string(payload[4:]) == "sftp"
}

func relaxSftpConsolePolicy() bool {
	return config.Get().System.Sftp.AllowConsoleShell
}

func shellOrPowerAllowed(perms []string, need string) bool {
	if relaxSftpConsolePolicy() {
		return true
	}
	return hasPermission(perms, need)
}

func (c *SFTPServer) writeSSHConsoleBootstrap(srv *server.Server, out *sshChannelOut, sshUser string) {
	sid := srv.ID()
	short := sid
	if len(sid) > 8 {
		short = sid[:8] + "..."
	}
	state := srv.Environment.State()

	var sb strings.Builder
	sb.WriteString(renderSSHWelcomeScreen(sshUser, short, sid, state))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if running, _ := srv.Environment.IsRunning(ctx); running {
		lines, err := srv.Environment.Readlog(config.Get().System.WebsocketLogCount)
		if err != nil {
			sb.WriteString(renderSSHReadLogError(err))
			sb.WriteString("\n")
		} else {
			sb.WriteString(renderSSHLogPreamble(len(lines)))
			sb.WriteString("\n  ")
			sb.WriteString(lipMuted.Render(strings.Repeat("-", sshUIViewWidth-4)))
			sb.WriteString("\n")
			for _, line := range lines {
				sb.WriteString(line)
				if len(line) == 0 || line[len(line)-1] != '\n' {
					sb.WriteString("\n")
				}
			}
		}
	} else {
		sb.WriteString(renderSSHLogEmpty())
		sb.WriteString("\n")
	}
	sb.WriteString(renderSSHLogFooter())

	_ = out.WriteRenderedBlock(sb.String())
}

// handleConsole bridges an SSH session channel to the game server console, mirroring websocket
// command input and log output (LogSink) behavior.
func (c *SFTPServer) handleConsole(conn *ssh.ServerConn, srv *server.Server, channel ssh.Channel, userUUID, ip string, perms []string) {
	ctx, cancel := context.WithCancel(srv.Sftp().Context(userUUID))
	defer cancel()
	defer func() { _ = channel.Close() }()

	out := &sshChannelOut{ch: channel}

	logger := srv.Log().WithFields(log.Fields{
		"subsystem": "sftp_console",
		"user":      userUUID,
		"ip":        ip,
	})

	ra := srv.NewRequestActivity("", ip).SetUser(userUUID)

	c.writeSSHConsoleBootstrap(srv, out, conn.User())

	// Large buffer so bursts from the game process do not block SinkPool.Push on this sink.
	logCh := make(chan []byte, 512)
	srv.Sink(system.LogSink).On(logCh)
	defer srv.Sink(system.LogSink).Off(logCh)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case line, ok := <-logCh:
				if !ok {
					return
				}
				// One write per line: fewer mutex round-trips to the SSH channel.
				var payload []byte
				if len(line) > 0 && line[len(line)-1] != '\n' {
					payload = make([]byte, 0, len(line)+2)
					payload = append(payload, line...)
					payload = append(payload, '\r', '\n')
				} else {
					payload = line
				}
				if err := out.WriteRaw(payload); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	buf := make([]byte, 4096)
	var lineBuf bytes.Buffer

outer:
	for {
		if ctx.Err() != nil {
			break
		}

		n, err := channel.Read(buf)
		if n > 0 {
			abortBuf := false
			for i := 0; i < n && !abortBuf; i++ {
				b := buf[i]
				switch b {
				case '\n', '\r':
					cmd := strings.TrimSpace(lineBuf.String())
					lineBuf.Reset()
					if werr := out.WriteRaw([]byte("\r\n")); werr != nil {
						cancel()
						abortBuf = true
						break
					}
					if cmd == "" {
						break
					}
					sendErr := c.sendConsoleLine(srv, out, ra, perms, cmd)
					if sendErr != nil {
						if errors.Is(sendErr, ErrSSHConsoleDisconnect) {
							break outer
						}
						if !errors.Is(sendErr, server.ErrSuspended) {
							logger.WithField("error", sendErr).Debug("ssh console: command failed")
						}
					}
				case 127, 8: // DEL, BS — PuTTY / common terminals
					if lineBuf.Len() > 0 {
						lineBuf.Truncate(lineBuf.Len() - 1)
						_ = out.WriteRaw([]byte("\b \b"))
					}
				default:
					// Echo printable ASCII, tab, and UTF-8 (extended bytes) so typing is visible.
					if b == '\t' || b >= 32 {
						lineBuf.WriteByte(b)
						if werr := out.WriteRaw([]byte{b}); werr != nil {
							cancel()
							abortBuf = true
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}

	cancel()
	wg.Wait()
}

func (c *SFTPServer) sendConsoleLine(srv *server.Server, out *sshChannelOut, ra server.RequestActivity, perms []string, cmd string) error {
	cmd = normalizeSSHConsoleInput(strings.TrimSpace(cmd))

	if handled, err := c.handleSSHConsoleMeta(srv, out, ra, perms, cmd); handled {
		return err
	}

	if srv.IsSuspended() {
		outErr(out, "This server is suspended.")
		return server.ErrSuspended
	}

	state := srv.Environment.State()
	if state == environment.ProcessOfflineState {
		app := sshConfiguredAppName()
		msg := lipMuted.Render("Process is offline. Run ") +
			lipKey.Render(sshConsoleMetaPrefix+" start") +
			lipMuted.Render(" or from the "+app+" panel. Daemon help: ") +
			lipKey.Render(".help")
		_ = out.WriteRenderedBlock(viewNote(msg))
		return nil
	}

	if state == environment.ProcessStartingState {
		if e, ok := srv.Environment.(*docker.Environment); ok {
			if !e.IsAttached() {
				outWarn(out, "Server is still starting — console attach not ready. Try again in a moment.")
				return nil
			}
		}
	}

	if !relaxSftpConsolePolicy() && !hasPermission(perms, permissionConsole) {
		outErr(out, "Your account does not have %s permission for in-game commands.", permissionConsole)
		return nil
	}

	if err := srv.Environment.SendCommand(cmd); err != nil {
		outErr(out, "%v", err)
		return err
	}

	srv.SaveActivity(ra, server.ActivityConsoleCommand, models.ActivityMeta{
		"command": cmd,
	})
	return nil
}

func (c *SFTPServer) handleSSHConsoleMeta(srv *server.Server, out *sshChannelOut, ra server.RequestActivity, perms []string, cmd string) (bool, error) {
	parts := strings.Fields(cmd)
	if len(parts) < 2 || !strings.EqualFold(parts[0], sshConsoleMetaPrefix) {
		return false, nil
	}

	sub := strings.ToLower(parts[1])

	switch sub {
	case "help", "?":
		_ = out.WriteRenderedBlock(renderSSHHelp())
		return true, nil

	case "status":
		_ = out.WriteRenderedBlock(renderSSHStatusPanel(srv.Environment.State()))
		return true, nil

	case "logs":
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		if running, _ := srv.Environment.IsRunning(ctx); !running {
			outWarn(out, "No running process — nothing to read from logs yet.")
			return true, nil
		}
		lines, err := srv.Environment.Readlog(config.Get().System.WebsocketLogCount)
		if err != nil {
			outErr(out, "%v", err)
			return true, err
		}
		_ = out.WriteRenderedBlock(renderSSHScrollbackHeader(len(lines)))
		for _, line := range lines {
			if err := out.WriteLineRaw(line); err != nil {
				return true, err
			}
		}
		outRule(out)
		return true, nil

	case "start":
		return true, c.sshConsolePower(srv, out, ra, perms, server.PowerActionStart, permissionSendPowerStart)

	case "stop":
		return true, c.sshConsolePower(srv, out, ra, perms, server.PowerActionStop, permissionSendPowerStop)

	case "restart":
		return true, c.sshConsolePower(srv, out, ra, perms, server.PowerActionRestart, permissionSendPowerRestart)

	case "kill", "terminate":
		return true, c.sshConsolePower(srv, out, ra, perms, server.PowerActionTerminate, permissionSendPowerStop)

	case "exit", "quit", "bye", "disconnect":
		_ = out.WriteRenderedBlock(viewOK("Goodbye — closing this SSH session."))
		return true, ErrSSHConsoleDisconnect

	case "clear", "cls":
		// Clear screen + home cursor (common ANSI; works in PuTTY, Windows Terminal, xterm).
		_ = out.WriteRaw([]byte("\x1b[2J\x1b[H"))
		return true, nil

	case "about", "version":
		_ = out.WriteRenderedBlock(renderSSHAbout())
		return true, nil

	case "echo":
		msg := strings.TrimSpace(strings.Join(parts[2:], " "))
		if msg == "" {
			_ = out.WriteRenderedBlock(lipMuted.Render("(echo: no text)"))
		} else {
			_ = out.WriteRenderedBlock(lipMuted.Render(msg))
		}
		return true, nil

	default:
		hint := fmt.Sprintf("Unknown %q — run ", parts[1]) + lipKey.Render(".help") + lipMuted.Render(" for a command list.")
		_ = out.WriteRenderedBlock(viewWarn(hint))
		return true, nil
	}
}

func (c *SFTPServer) sshConsolePower(srv *server.Server, out *sshChannelOut, ra server.RequestActivity, perms []string, action server.PowerAction, needPerm string) error {
	if srv.IsSuspended() {
		outErr(out, "This server is suspended.")
		return server.ErrSuspended
	}

	if !shellOrPowerAllowed(perms, needPerm) {
		outErr(out, "You are not allowed to run %q for this server.", action)
		return nil
	}

	err := srv.HandlePowerAction(action)
	if err != nil {
		if errors.Is(err, system.ErrLockerLocked) {
			outWarn(out, "Another power action is already running — try again shortly.")
			return nil
		}
		outErr(out, "Power %s: %v", action, err)
		return err
	}

	outOK(out, "Power action %q has been accepted.", string(action))
	srv.SaveActivity(ra, models.Event(server.ActivityPowerPrefix+string(action)), nil)
	return nil
}
