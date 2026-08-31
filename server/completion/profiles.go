package completion

import "strings"

// Builtin returns a named built-in completion profile, or nil if unknown.
// Profiles are optional conveniences; any egg can ship a full Tree via
// process_configuration.completion instead.
func Builtin(name string) *Tree {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "minecraft", "mc", "paper", "purpur", "spigot", "bukkit", "folia":
		return Minecraft()
	default:
		return nil
	}
}

// ResolveTree picks a completion tree for a server console.
//
// Order:
//  1. Explicit egg/process tree (any app) — wins when non-empty
//  2. Egg feature "console_completion" listing built-in profile names
//  3. Auto-detect a known built-in (currently Minecraft) as a convenience
func ResolveTree(explicit *Tree, features map[string][]string, image, invocation string) *Tree {
	return ResolveTreeEnv(explicit, features, image, invocation, nil)
}

// ResolveTreeEnv is ResolveTree with egg environment variables for auto-detect.
func ResolveTreeEnv(explicit *Tree, features map[string][]string, image, invocation string, env map[string]string) *Tree {
	if explicit != nil && len(explicit.Commands) > 0 {
		return explicit
	}

	if features != nil {
		if names, ok := features["console_completion"]; ok {
			for _, name := range names {
				if tree := Builtin(name); tree != nil {
					return tree
				}
			}
		}
	}

	// Bonus: detect a few well-known stacks without egg config.
	if LooksLikeMinecraftEnv(image, invocation, features, env) {
		return Minecraft()
	}
	return nil
}
