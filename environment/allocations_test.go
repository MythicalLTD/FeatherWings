package environment

import (
	"path/filepath"
	"testing"

	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mythicalltd/featherwings/config"
)

// Loopback bindings are removed when ISPN is enabled, including a port that is
// listed more than once.
func TestDockerBindingsIspnHandlesRepeatedLoopbackPort(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	cfg.Docker.Network.ISPN = true
	config.Set(cfg)

	a := Allocations{Mappings: map[string][]int{"127.0.0.1": {25565, 25565}}}
	require.NotPanics(t, func() {
		out := a.DockerBindings()
		assert.Empty(t, out["25565/tcp"])
		assert.Empty(t, out["25565/udp"])
	})
}

// Without ISPN, loopback bindings use the Docker network interface and other
// bindings are kept.
func TestDockerBindingsReplaceLoopbackAddress(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	cfg.Docker.Network.Interface = "172.18.0.1"
	config.Set(cfg)

	a := Allocations{Mappings: map[string][]int{"127.0.0.1": {25565}, "10.0.0.5": {25565}}}
	out := a.DockerBindings()
	var ips []string
	for _, b := range out["25565/tcp"] {
		ips = append(ips, b.HostIP)
	}
	assert.ElementsMatch(t, []string{"172.18.0.1", "10.0.0.5"}, ips)
}

// A port whose only bindings are loopback ones is removed entirely under ISPN.
// Docker fills an empty binding list with a binding on every interface at a
// random host port, so an empty list must never be returned.
func TestDockerBindingsIspnRemovesPortWithoutBindings(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	cfg.Docker.Network.ISPN = true
	config.Set(cfg)

	a := Allocations{Mappings: map[string][]int{
		"127.0.0.1": {25565, 25566},
		"10.0.0.5":  {25566},
	}}
	out := a.DockerBindings()
	for port, binds := range out {
		assert.NotEmpty(t, binds, "port %s has an empty binding list", port)
	}
	assert.NotContains(t, out, nat.Port("25565/tcp"))
	assert.NotContains(t, out, nat.Port("25565/udp"))
	require.Len(t, out["25566/tcp"], 1)
	assert.Equal(t, "10.0.0.5", out["25566/tcp"][0].HostIP)

	exposed := a.Exposed()
	assert.NotContains(t, exposed, nat.Port("25565/tcp"))
	assert.Contains(t, exposed, nat.Port("25566/tcp"))
}
