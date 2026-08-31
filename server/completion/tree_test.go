package completion

import (
	"sort"
	"testing"

	. "github.com/franela/goblin"
)

func TestSuggest(t *testing.T) {
	g := Goblin(t)
	tree := Minecraft()

	g.Describe("Suggest", func() {
		g.It("suggests command names for a prefix", func() {
			line := "/gam"
			resp := Suggest(tree, line, len(line))
			g.Assert(contains(resp.Suggestions, "gamemode")).IsTrue()
			g.Assert(contains(resp.Suggestions, "/gamemode")).IsFalse()
			g.Assert(resp.Start).Equal(1) // keep leading "/"
			g.Assert(resp.End).Equal(len(line))
		})

		g.It("suggests bare command names without a slash typed", func() {
			line := "gam"
			resp := Suggest(tree, line, len(line))
			g.Assert(contains(resp.Suggestions, "gamemode")).IsTrue()
			g.Assert(resp.Start).Equal(0)
		})

		g.It("offers first-arg values when the command name is exact", func() {
			line := "/gamemode"
			resp := Suggest(tree, line, len(line))
			sort.Strings(resp.Suggestions)
			g.Assert(resp.Suggestions).Equal([]string{"adventure", "creative", "spectator", "survival"})
			g.Assert(resp.Start).Equal(len(line))
			g.Assert(resp.End).Equal(len(line))
		})

		g.It("suggests gamemode values after the command", func() {
			line := "/gamemode "
			resp := Suggest(tree, line, len(line))
			sort.Strings(resp.Suggestions)
			g.Assert(resp.Suggestions).Equal([]string{"adventure", "creative", "spectator", "survival"})
			g.Assert(resp.Start).Equal(len(line))
			g.Assert(resp.End).Equal(len(line))
		})


		g.It("filters gamemode values by prefix", func() {
			line := "/gamemode c"
			resp := Suggest(tree, line, len(line))
			g.Assert(resp.Suggestions).Equal([]string{"creative"})
			g.Assert(resp.Start).Equal(len("/gamemode "))
			g.Assert(resp.End).Equal(len(line))
		})

		g.It("returns empty for unknown commands", func() {
			line := "/notacommand "
			resp := Suggest(tree, line, len(line))
			g.Assert(len(resp.Suggestions)).Equal(0)
		})

		g.It("returns empty for a nil tree", func() {
			resp := Suggest(nil, "/gamemode ", 10)
			g.Assert(len(resp.Suggestions)).Equal(0)
		})

		g.It("respects cursor before end of line", func() {
			line := "/gamemode creative"
			resp := Suggest(tree, line, len("/gamemode c"))
			g.Assert(resp.Suggestions).Equal([]string{"creative"})
		})

		g.It("suggests difficulty values", func() {
			line := "/difficulty "
			resp := Suggest(tree, line, len(line))
			g.Assert(contains(resp.Suggestions, "peaceful")).IsTrue()
			g.Assert(contains(resp.Suggestions, "hard")).IsTrue()
		})

		g.It("suggests gamerule names", func() {
			line := "/gamerule keep"
			resp := Suggest(tree, line, len(line))
			g.Assert(resp.Suggestions).Equal([]string{"keepInventory"})
		})
	})
}

func TestLooksLikeMinecraft(t *testing.T) {
	g := Goblin(t)

	g.Describe("LooksLikeMinecraft", func() {
		g.It("matches paper images", func() {
			g.Assert(LooksLikeMinecraft("ghcr.io/pterodactyl/yolks:java_21", "java -jar paper.jar", nil)).IsTrue()
		})

		g.It("matches eula feature", func() {
			g.Assert(LooksLikeMinecraft("custom:latest", "java -jar server.jar", map[string][]string{
				"eula": {"You need to agree"},
			})).IsTrue()
		})

		g.It("rejects unrelated eggs", func() {
			g.Assert(LooksLikeMinecraft("redis:7", "redis-server", nil)).IsFalse()
		})
	})
}

func TestResolveTree(t *testing.T) {
	g := Goblin(t)

	g.Describe("ResolveTree", func() {
		g.It("prefers an explicit egg tree for any app", func() {
			explicit := &Tree{Commands: map[string]Command{
				"ping": {Args: []ArgSpec{{Values: []string{"pong"}}}},
			}}
			tree := ResolveTree(explicit, map[string][]string{
				"console_completion": {"minecraft"},
			}, "paper:latest", "java -jar paper.jar")
			g.Assert(tree).Equal(explicit)
			resp := Suggest(tree, "ping ", 5)
			g.Assert(resp.Suggestions).Equal([]string{"pong"})
		})

		g.It("uses console_completion feature for built-in profiles", func() {
			tree := ResolveTree(nil, map[string][]string{
				"console_completion": {"minecraft"},
			}, "redis:7", "redis-server")
			g.Assert(tree != nil).IsTrue()
			resp := Suggest(tree, "/gamemode ", len("/gamemode "))
			g.Assert(contains(resp.Suggestions, "creative")).IsTrue()
		})

		g.It("returns nil when nothing matches", func() {
			tree := ResolveTree(nil, nil, "redis:7", "redis-server")
			g.Assert(tree == nil).IsTrue()
		})
	})
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
