package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigurePasswdWritesPasswdAndGroup(t *testing.T) {
	dir := t.TempDir()
	c, err := NewAtPath(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	c.AuthenticationToken = "test-token"
	c.System.User.Uid = 988
	c.System.User.Gid = 987
	c.System.User.PasswdFile = filepath.Join(dir, "etc", "passwd")
	c.System.User.GroupFile = filepath.Join(dir, "etc", "group")
	Set(c)

	if !c.System.User.Passwd {
		t.Fatal("expected mount_passwd to default to true")
	}
	if err := ConfigurePasswd(); err != nil {
		t.Fatalf("ConfigurePasswd() error = %v", err)
	}

	for path, want := range map[string]string{
		c.System.User.PasswdFile: "container:x:988:987::/home/container:/usr/sbin/nologin\n",
		c.System.User.GroupFile:  "container:x:987:container\n",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", path, got, want)
		}
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0o644 {
			t.Fatalf("%s mode = %v, want 0644", path, st.Mode().Perm())
		}
	}
}

func TestConfigurePasswdDisabledWritesNothing(t *testing.T) {
	dir := t.TempDir()
	c, err := NewAtPath(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	c.AuthenticationToken = "test-token"
	c.System.User.Passwd = false
	c.System.User.PasswdFile = filepath.Join(dir, "passwd")
	c.System.User.GroupFile = filepath.Join(dir, "group")
	Set(c)

	if err := ConfigurePasswd(); err != nil {
		t.Fatalf("ConfigurePasswd() error = %v", err)
	}
	for _, p := range []string{c.System.User.PasswdFile, c.System.User.GroupFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected %s not to be written, stat error = %v", p, err)
		}
	}
}

func TestGroupFileDefault(t *testing.T) {
	c, err := NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.System.User.GroupFile != "/etc/featherpanel/group" {
		t.Fatalf("GroupFile default = %q", c.System.User.GroupFile)
	}
}
