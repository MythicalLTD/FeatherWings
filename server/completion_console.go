package server

import (
	"fmt"

	"github.com/goccy/go-json"

	"github.com/mythicalltd/featherwings/server/completion"
)

// ConsoleSuggest returns Tab-completion suggestions for any server console.
// The panel sends the partial line on Tab; Wings returns suggestions from a
// static tree (egg-defined for any app, or an optional built-in profile).
func (s *Server) ConsoleSuggest(req completion.Request) completion.Response {
	cursor := completion.NormalizeCursor(req.Line, req.Cursor)
	resp := completion.Suggest(s.completionTree(), req.Line, cursor)
	resp.ID = req.ID
	resp.Line = req.Line
	resp.Cursor = cursor
	if resp.Suggestions == nil {
		resp.Suggestions = []string{}
	}
	return resp
}

func (s *Server) completionTree() *completion.Tree {
	var explicit *completion.Tree
	if pc := s.ProcessConfiguration(); pc != nil && len(pc.Completion) > 0 {
		var tree completion.Tree
		if err := json.Unmarshal(pc.Completion, &tree); err == nil && len(tree.Commands) > 0 {
			explicit = &tree
		}
	}

	cfg := s.Config()
	env := map[string]string{}
	for k, v := range cfg.EnvVars {
		env[k] = fmt.Sprint(v)
	}
	return completion.ResolveTreeEnv(explicit, cfg.Egg.Features, cfg.Container.Image, cfg.Invocation, env)
}
