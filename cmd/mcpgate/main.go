package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

// Version is the semantic version of MCPGate, overridable via:
// -ldflags "-X main.Version=1.0.1"
var Version = "1.0.1"

// exitError signals a non-zero exit code without re-printing usage or duplicate error text.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string {
	return e.msg
}

func main() {
	code := runCLI(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if code != 0 {
		os.Exit(code)
	}
}

func runCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	root := newRootCmd(stdin, stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return 0
	}

	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			fmt.Fprintln(stderr, ee.msg)
		}
		if ee.code == 0 {
			return 1
		}
		return ee.code
	}

	fmt.Fprintf(stderr, "mcpgate: %v\n", err)
	return 1
}

func newRootCmd(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "mcpgate",
		Short:         "Zero-Trust Local Firewall, Sandbox & DLP Proxy for MCP Servers",
		Long:          "MCPGate wraps local Model Context Protocol (MCP) servers with zero-trust tool poisoning quarantine, SHA-256 rug-pull schema lockfiles, live DLP secret scanning, SSRF-safe egress firewalling, and OS process sandboxing.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)

	root.AddCommand(
		newRunCmd(stdin, stdout, stderr),
		newAuditCmd(stdout, stderr),
		newLockCmd(stdout, stderr),
		newTestPolicyCmd(stdout, stderr),
		newInspectCmd(stdout, stderr),
		newDoctorCmd(stdout, stderr),
		newPresetCmd(stdout, stderr),
		newMCPCmd(stdin, stdout, stderr),
		newVersionCmd(stdout),
	)

	return root
}

func newVersionCmd(stdout io.Writer) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print MCPGate version and build environment information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := map[string]string{
				"version":    Version,
				"go_version": runtime.Version(),
				"os":         runtime.GOOS,
				"arch":       runtime.GOARCH,
			}
			if asJSON {
				return writeIndentedJSON(stdout, info)
			}
			fmt.Fprintf(stdout, "mcpgate v%s (%s/%s, %s)\n", Version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Output version metadata as JSON")
	return cmd
}
