package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func executeValidate(args ...string) (stdout, stderr string, err error) {
	outBuf := new(bytes.Buffer)
	errBuf := new(bytes.Buffer)
	cmd := rootCmd
	cmd.SetOut(outBuf)
	cmd.SetErr(errBuf)
	cmd.SetArgs(append([]string{"validate"}, args...))
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

func TestValidateCommand_ValidConfig(t *testing.T) {
	content := `listenAddr: ":9090"
warnBefore: 720h
critBefore: 336h
refreshEvery: 2m
`
	path := filepath.Join(t.TempDir(), "valid.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := executeValidate(path)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !strings.Contains(stdout, "config OK") {
		t.Errorf("expected 'config OK' in output, got: %q", stdout)
	}
}

func TestValidateCommand_InvalidConfig(t *testing.T) {
	content := `listenAddr: ""
warnBefore: 720h
critBefore: 336h
refreshEvery: 2m
`
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeValidate(path)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
	if !strings.Contains(stderr, "listenAddr") {
		t.Errorf("expected 'listenAddr' in stderr, got: %q", stderr)
	}
}

func TestValidateCommand_MissingFile(t *testing.T) {
	_, _, err := executeValidate("/tmp/nonexistent-trustwatch-config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateCommand_BadYAML(t *testing.T) {
	content := `{{{not: valid: yaml`
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := executeValidate(path)
	if err == nil {
		t.Fatal("expected error for bad YAML")
	}
}
