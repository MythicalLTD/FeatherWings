package server

import "testing"

func TestResolveImportPath(t *testing.T) {
	base := "/var/lib/featherpanel/volumes/0f6c1a54-1111-2222-3333-444455556666"

	allowed := []string{"", "/", "/world", "world/level.dat", "./plugins/./x.jar"}
	for _, dst := range allowed {
		if _, err := resolveImportPath(base, dst); err != nil {
			t.Errorf("resolveImportPath(%q) wurde abgelehnt, erwartet erlaubt: %v", dst, err)
		}
	}

	denied := []string{
		"..",
		"../",
		"../../etc/cron.d",
		"../../../../../etc/authorized_keys",
		"/../etc/shadow",
		"world/../../../etc/passwd",
	}
	for _, dst := range denied {
		if got, err := resolveImportPath(base, dst); err == nil {
			t.Errorf("resolveImportPath(%q) wurde erlaubt (%q), erwartet abgelehnt", dst, got)
		}
	}
}
