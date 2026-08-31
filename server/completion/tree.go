package completion

import (
	"strings"
	"unicode"
)

// Tree is a static CLI completion tree for a server console.
// Commands map the first token (without a leading slash) to argument specs.
type Tree struct {
	Commands map[string]Command `json:"commands"`
}

// Command describes sequential argument completions for a command.
type Command struct {
	// Args[i] is the completion spec for the i-th argument after the command name.
	Args []ArgSpec `json:"args"`
}

// ArgSpec is either a fixed set of literal values or free-form input (Any).
type ArgSpec struct {
	Values []string `json:"values,omitempty"`
	Any    bool     `json:"any,omitempty"`
}

// Request is the inbound suggest-command payload.
type Request struct {
	ID     string `json:"id"`
	Line   string `json:"line"`
	Cursor int    `json:"cursor"`
}

// Response is returned to the panel for Tab completion.
type Response struct {
	ID          string   `json:"id"`
	Line        string   `json:"line"`
	Cursor      int      `json:"cursor"`
	Start       int      `json:"start"`
	End         int      `json:"end"`
	Suggestions []string `json:"suggestions"`
}

// Suggest walks tree for the partial line and returns prefix-filtered matches
// plus the byte range [Start, End) that the panel should replace.
//
// Token rules (prefix = line[:cursor]):
//   - "/gam"              → command names matching "gam"
//   - "/gamemode "        → first-arg values
//   - "/gamemode c"       → first-arg values matching "c"
//   - "/gamemode survival " → second-arg values (if defined)
func Suggest(tree *Tree, line string, cursor int) Response {
	cursor = NormalizeCursor(line, cursor)
	resp := Response{
		Line:        line,
		Cursor:      cursor,
		Suggestions: []string{},
		Start:       cursor,
		End:         cursor,
	}
	if tree == nil || len(tree.Commands) == 0 {
		return resp
	}

	prefix := line[:cursor]
	start, end, completed, partial := tokenize(prefix)
	resp.Start = start
	resp.End = end

		// Still typing the command name (no completed tokens yet).
		// Suggestions are bare names (no leading "/"); Minecraft consoles
		// treat "/" as optional/automatic.
		if len(completed) == 0 {
			name := strings.TrimPrefix(partial, "/")
			matches := filterPrefix(commandNames(tree), name)

			// Exact command already typed (e.g. "gamemode" or "/gamemode") →
			// offer first-arg completions the same way a trailing space would.
			if name != "" {
				if cmd, ok := lookupCommand(tree, name); ok && len(cmd.Args) > 0 && !cmd.Args[0].Any {
					exact := false
					for _, m := range matches {
						if strings.EqualFold(strings.TrimPrefix(m, "/"), name) {
							exact = true
							break
						}
					}
					if exact && len(matches) == 1 {
						resp.Start = len(prefix)
						resp.End = len(prefix)
						resp.Suggestions = filterPrefix(cmd.Args[0].Values, "")
						return resp
					}
				}
			}

			// If the user typed a leading "/", only replace the name after it
			// so accepting "gamemode" turns "/gam" into "/gamemode".
			if strings.HasPrefix(partial, "/") && start < end {
				resp.Start = start + 1
			}

			resp.Suggestions = matches
			return resp
		}

	cmdName := strings.TrimPrefix(completed[0], "/")
	cmd, ok := lookupCommand(tree, cmdName)
	if !ok {
		// Unknown command while editing the first token — fall back to command names.
		if len(completed) == 1 && !strings.HasSuffix(prefix, " ") {
			// completed incorrectly includes the in-progress token only when
			// trailing space is absent and tokenize moved it to partial.
			// If we are here with completed[0] set, the command token is finished.
			return resp
		}
		return resp
	}

	// Argument index: number of completed tokens after the command name.
	// "/gamemode" + partial "c" → completed=["gamemode"], argIdx=0
	// "/gamemode " → completed=["gamemode"], partial="", argIdx=0
	// "/gamemode survival x" → completed=["gamemode","survival"], partial="x", argIdx=1
	argIdx := len(completed) - 1
	if argIdx < 0 {
		return resp
	}
	if argIdx >= len(cmd.Args) {
		return resp
	}

	spec := cmd.Args[argIdx]
	if spec.Any {
		return resp
	}
	resp.Suggestions = filterPrefix(spec.Values, partial)
	return resp
}

func lookupCommand(tree *Tree, name string) (Command, bool) {
	if cmd, ok := tree.Commands[name]; ok {
		return cmd, true
	}
	if cmd, ok := tree.Commands[strings.ToLower(name)]; ok {
		return cmd, true
	}
	for k, cmd := range tree.Commands {
		if strings.EqualFold(k, name) {
			return cmd, true
		}
	}
	return Command{}, false
}

// tokenize splits prefix into completed tokens and the in-progress partial token.
// start/end are the replace range for the partial token within prefix.
func tokenize(prefix string) (start, end int, completed []string, partial string) {
	end = len(prefix)
	if prefix == "" {
		return 0, 0, nil, ""
	}

	if strings.HasSuffix(prefix, " ") {
		fields := strings.Fields(prefix)
		return len(prefix), end, fields, ""
	}

	fields := strings.Fields(prefix)
	if len(fields) == 0 {
		return 0, end, nil, ""
	}

	partial = fields[len(fields)-1]
	completed = fields[:len(fields)-1]
	start = strings.LastIndex(prefix, partial)
	if start < 0 {
		start = len(prefix) - len(partial)
	}
	return start, end, completed, partial
}

func commandNames(tree *Tree) []string {
	out := make([]string, 0, len(tree.Commands))
	for name := range tree.Commands {
		out = append(out, name)
	}
	return out
}

func filterPrefix(values []string, prefix string) []string {
	if len(values) == 0 {
		return []string{}
	}
	prefix = strings.ToLower(prefix)
	out := make([]string, 0, len(values))
	for _, v := range values {
		if prefix == "" || strings.HasPrefix(strings.ToLower(v), prefix) {
			out = append(out, v)
		}
	}
	return out
}

// LooksLikeMinecraft reports whether server metadata suggests a Minecraft egg.
func LooksLikeMinecraft(image, invocation string, features map[string][]string) bool {
	return LooksLikeMinecraftEnv(image, invocation, features, nil)
}

// LooksLikeMinecraftEnv is like LooksLikeMinecraft but also checks egg environment
// variables (e.g. MINECRAFT_VERSION, SERVER_JARFILE) which are more reliable than
// the unresolved {{SERVER_JARFILE}} startup template.
func LooksLikeMinecraftEnv(image, invocation string, features map[string][]string, env map[string]string) bool {
	hay := strings.ToLower(image + " " + invocation)
	for k, v := range env {
		hay += " " + strings.ToLower(k) + "=" + strings.ToLower(v)
	}
	needles := []string{
		"minecraft", "paper", "purpur", "spigot", "bukkit", "fabric", "forge",
		"quilt", "neoforge", "velocity", "bungeecord", "waterfall", "folia",
		"leavesmc", "pufferfish", "airplane", "tuinity", "server_jarfile",
		"minecraft_version", "server.jar",
	}
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	if features != nil {
		if _, ok := features["eula"]; ok {
			return true
		}
		for key := range features {
			lk := strings.ToLower(key)
			if strings.Contains(lk, "minecraft") || strings.Contains(lk, "eula") {
				return true
			}
		}
	}
	if strings.Contains(hay, "java") && (strings.Contains(hay, "server.jar") ||
		strings.Contains(hay, "paper.jar") || strings.Contains(hay, "purpur.jar") ||
		strings.Contains(hay, "server_jarfile")) {
		return true
	}
	return false
}

// NormalizeCursor clamps cursor into [0, len(line)].
func NormalizeCursor(line string, cursor int) int {
	if cursor < 0 {
		return 0
	}
	if cursor > len(line) {
		return len(line)
	}
	if cursor < len(line) && !utf8SafeAt(line, cursor) {
		for cursor > 0 && !utf8SafeAt(line, cursor) {
			cursor--
		}
	}
	return cursor
}

func utf8SafeAt(s string, i int) bool {
	if i == 0 || i == len(s) {
		return true
	}
	r := rune(s[i])
	return unicode.IsPrint(r) || r == '\t' || r < unicode.MaxASCII
}
