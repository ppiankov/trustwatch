package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ppiankov/trustwatch/internal/drift"
	"github.com/ppiankov/trustwatch/internal/monitor"
	"github.com/ppiankov/trustwatch/internal/store"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage certificate baselines for drift detection",
	Long: `Save or check a certificate baseline.

A baseline captures a known-good certificate inventory as JSON.
Compare future scans against it to detect unauthorized additions,
removals, or issuer/serial changes.`,
}

var baselineSaveCmd = &cobra.Command{
	Use:   "save",
	Short: "Save a snapshot as a baseline file",
	Long: `Read a JSON snapshot from stdin and write it as a baseline file.

Usage:
  trustwatch now -o json | trustwatch baseline save -o baseline.json
  curl -s http://localhost:8080/api/v1/snapshot | trustwatch baseline save -o baseline.json`,
	RunE: runBaselineSave,
}

var baselineCheckCmd = &cobra.Command{
	Use:   "check <baseline.json>",
	Short: "Compare a current scan against a baseline",
	Long: `Read a current JSON snapshot from stdin and compare against a baseline file.

Exits 0 if no drift is detected, 1 if drift is found.

Usage:
  trustwatch now -o json | trustwatch baseline check baseline.json`,
	Args: cobra.ExactArgs(1),
	RunE: runBaselineCheck,
}

func init() {
	rootCmd.AddCommand(baselineCmd)
	baselineCmd.AddCommand(baselineSaveCmd)
	baselineCmd.AddCommand(baselineCheckCmd)
	baselineSaveCmd.Flags().StringP("output", "o", "baseline.json", "Output file path")
}

func runBaselineSave(cmd *cobra.Command, _ []string) error {
	outPath, _ := cmd.Flags().GetString("output") //nolint:errcheck // flag registered above

	snap, err := readSnapshotFromStdin(cmd.InOrStdin())
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing baseline: %w", err)
	}

	cmd.Printf("baseline saved to %s (%d findings)\n", outPath, len(snap.Findings))
	return nil
}

func runBaselineCheck(cmd *cobra.Command, args []string) error {
	// Load baseline
	baselineData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("reading baseline: %w", err)
	}
	var baseline store.Snapshot
	if unmarshalErr := json.Unmarshal(baselineData, &baseline); unmarshalErr != nil {
		return fmt.Errorf("parsing baseline: %w", unmarshalErr)
	}

	// Read current snapshot from stdin
	current, err := readSnapshotFromStdin(cmd.InOrStdin())
	if err != nil {
		return err
	}

	// Compare
	driftFindings := drift.Detect(baseline.Findings, current.Findings)

	if len(driftFindings) == 0 {
		cmd.Println("no drift detected")
		return nil
	}

	cmd.Printf("%d drift finding(s) detected:\n", len(driftFindings))
	for i := range driftFindings {
		f := &driftFindings[i]
		cmd.Printf("  [%s] %s/%s: %s — %s\n", f.Severity, f.Namespace, f.Name, f.FindingType, f.Notes)
	}

	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	os.Exit(1) //nolint:gocritic // exitAfterDefer — intentional exit on drift
	return nil
}

// readSnapshotFromStdin reads a store.Snapshot from stdin.
// Accepts both raw Snapshot JSON and NowOutput envelope ({"snapshot": ...}).
func readSnapshotFromStdin(r io.Reader) (*store.Snapshot, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no input on stdin, pipe a snapshot via: trustwatch now -o json | trustwatch baseline save")
	}

	// Try NowOutput envelope first
	var envelope monitor.NowOutput
	if err := json.Unmarshal(data, &envelope); err == nil && !envelope.Snapshot.At.IsZero() {
		return &envelope.Snapshot, nil
	}

	// Fall back to raw Snapshot
	var snap store.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot JSON: %w", err)
	}
	return &snap, nil
}
