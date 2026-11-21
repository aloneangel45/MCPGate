//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

const seatbeltBinary = "/usr/bin/sandbox-exec"

func hasSeatbelt() bool {
	info, err := os.Stat(seatbeltBinary)
	return err == nil && !info.IsDir()
}

func platformCapabilities() HostCapabilities {
	caps := HostCapabilities{
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		ProcessIsolation:     "POSIX PGID (setpgid)",
		CleanEnvSupported:    true,
		FilesystemJail:       "Policy Path Guard (sandbox-exec unavailable)",
		MemoryLimitSupported: false,
		Details: []string{
			"Child processes run in a dedicated POSIX process group (Setpgid: true) for clean tree termination",
		},
	}

	if hasSeatbelt() {
		caps.FilesystemJail = "Seatbelt sandbox-exec"
		caps.Details = append(caps.Details, fmt.Sprintf("macOS Seatbelt detected at %s", seatbeltBinary))
	} else {
		caps.Details = append(caps.Details, fmt.Sprintf("macOS Seatbelt binary not found at %s", seatbeltBinary))
	}

	return caps
}

func preparePlatformCommand(cfg policy.SandboxPolicy, name string, args []string) (string, []string, []string, []string) {
	if !cfg.UseSeatbelt || !hasSeatbelt() {
		return name, args, nil, nil
	}

	profile := GenerateSeatbeltProfile(cfg.WorkDir, strings.TrimSpace(cfg.WorkDir) != "")
	f, err := os.CreateTemp("", "mcpgate-seatbelt-*.sb")
	if err != nil {
		// Graceful fallback if temp profile cannot be created.
		return name, args, nil, nil
	}
	profilePath := f.Name()
	if _, err := f.WriteString(profile); err != nil {
		_ = f.Close()
		_ = os.Remove(profilePath)
		return name, args, nil, nil
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(profilePath)
		return name, args, nil, nil
	}

	wrappedArgs := make([]string, 0, len(args)+4)
	wrappedArgs = append(wrappedArgs, "-f", profilePath, "--", name)
	wrappedArgs = append(wrappedArgs, args...)
	return seatbeltBinary, wrappedArgs, []string{"seatbelt_sandbox_exec"}, []string{profilePath}
}

func configurePlatformProcess(wc *WrappedCmd) error {
	wc.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	wc.Cmd.WaitDelay = 3 * time.Second
	wc.ActiveControls = append(wc.ActiveControls, "posix_pgid")

	killGroup := func() error {
		if wc.Cmd == nil || wc.Cmd.Process == nil || wc.Cmd.Process.Pid <= 0 {
			return nil
		}
		err := syscall.Kill(-wc.Cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	}

	wc.onKill = killGroup
	wc.onCleanup = killGroup
	return nil
}
