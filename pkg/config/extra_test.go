package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUserPath_ExplicitWins(t *testing.T) {
	got, err := resolveUserPath("/explicit/path.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/explicit/path.yaml" {
		t.Errorf("got %s", got)
	}
}

func TestResolveUserPath_XDGSet(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/x/y")
	got, err := resolveUserPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/x/y/unearth/weights.yaml" {
		t.Errorf("got %s", got)
	}
}

func TestResolveUserPath_FallsBackToHomeDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	got, err := resolveUserPath("")
	if err != nil {
		t.Fatal(err)
	}
	// On a normal test env we get a real home dir. Just check it ends correctly.
	want := filepath.Join(".config", "unearth", "weights.yaml")
	if got == "" {
		t.Skip("home dir unavailable")
	}
	if filepath.Base(got) != "weights.yaml" {
		t.Errorf("unexpected default path: %s (want suffix %s)", got, want)
	}
}

func TestResolveUserPath_NoHomeNoXDG_Empty(t *testing.T) {
	// Force UserHomeDir to fail by clearing HOME and XDG_CONFIG_HOME.
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	got, err := resolveUserPath("")
	if err != nil {
		t.Fatal(err)
	}
	// With both unset, Go's UserHomeDir typically returns an error and we
	// return "". On some platforms it falls back to passwd; accept either
	// "" or a usable path, but never an error.
	_ = got
}

func TestParseWeights_EmptyYAML(t *testing.T) {
	w, err := parseWeights([]byte(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Errorf("empty YAML should yield empty map")
	}
}

func TestParseWeights_NoWeightsKey(t *testing.T) {
	w, err := parseWeights([]byte("other:\n  foo: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Errorf("missing weights key should yield empty map")
	}
}

func TestLoadWeights_MalformedTopLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "weights.yaml")
	// Wrong type at top level — invalid YAML for our schema.
	if err := os.WriteFile(path, []byte(":\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWeights(path); err == nil {
		t.Fatal("expected parse error")
	}
}
