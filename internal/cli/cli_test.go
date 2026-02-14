package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRootCommand_Help(t *testing.T) {
	cmd := rootCmd
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("root --help failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "trustwatch") {
		t.Error("expected 'trustwatch' in help output")
	}
	if !strings.Contains(out, "serve") {
		t.Error("expected 'serve' subcommand in help output")
	}
	if !strings.Contains(out, "now") {
		t.Error("expected 'now' subcommand in help output")
	}
}

func TestVersionCommand(t *testing.T) {
	SetVersion("test-v0.0.1")
	defer SetVersion("dev")

	// version uses fmt.Println (stdout), so just verify the command exists and runs
	ver, _, err := rootCmd.Find([]string{"version"})
	if err != nil {
		t.Fatalf("failed to find 'version' command: %v", err)
	}
	if ver.Use != "version" {
		t.Errorf("expected Use='version', got %q", ver.Use)
	}
	if version != "test-v0.0.1" {
		t.Errorf("expected version 'test-v0.0.1', got %q", version)
	}
}

func TestRootCommand_LogFlags(t *testing.T) {
	cmd := rootCmd

	logLevel := cmd.PersistentFlags().Lookup("log-level")
	if logLevel == nil {
		t.Fatal("expected --log-level persistent flag")
	}
	if logLevel.DefValue != "info" {
		t.Errorf("expected default log-level 'info', got %q", logLevel.DefValue)
	}

	logFormat := cmd.PersistentFlags().Lookup("log-format")
	if logFormat == nil {
		t.Fatal("expected --log-format persistent flag")
	}
	if logFormat.DefValue != "text" {
		t.Errorf("expected default log-format 'text', got %q", logFormat.DefValue)
	}
}

func TestNowCommand_Flags(t *testing.T) {
	now, _, err := rootCmd.Find([]string{"now"})
	if err != nil {
		t.Fatalf("failed to find 'now' command: %v", err)
	}

	expectedFlags := []string{"context", "kubeconfig", "config", "warn-before", "crit-before", "tunnel", "tunnel-ns", "tunnel-image"}
	for _, name := range expectedFlags {
		if now.Flags().Lookup(name) == nil {
			t.Errorf("expected --%s flag on 'now' command", name)
		}
	}
}

func TestServeCommand_Flags(t *testing.T) {
	serve, _, err := rootCmd.Find([]string{"serve"})
	if err != nil {
		t.Fatalf("failed to find 'serve' command: %v", err)
	}

	expectedFlags := []string{"config", "listen", "kubeconfig", "context"}
	for _, name := range expectedFlags {
		if serve.Flags().Lookup(name) == nil {
			t.Errorf("expected --%s flag on 'serve' command", name)
		}
	}
}
