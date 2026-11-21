//go:build linux

package sandbox

import (
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

const (
	// Unified Linux syscall number for landlock_create_ruleset across modern architectures (kernel >= 5.13).
	sysLandlockCreateRuleset     = 444
	landlockCreateRulesetVersion = 1 << 0
)

func probeLandlockABI() (int, error) {
	abi, _, errno := syscall.Syscall(
		sysLandlockCreateRuleset,
		0,
		0,
		landlockCreateRulesetVersion,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(abi), nil
}

func platformCapabilities() HostCapabilities {
	caps := HostCapabilities{
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		ProcessIsolation:     "POSIX PGID (setpgid)",
		CleanEnvSupported:    true,
		FilesystemJail:       "Policy Path Guard (Landlock unavailable)",
		MemoryLimitSupported: false,
		Details: []string{
			"Child processes run in a dedicated POSIX process group (Setpgid: true) for clean tree termination",
		},
	}

	abi, err := probeLandlockABI()
	if err == nil && abi > 0 {
		caps.FilesystemJail = fmt.Sprintf("Landlock ABI v%d", abi)
		caps.Details = append(caps.Details, fmt.Sprintf("Linux Landlock LSM detected (ABI v%d)", abi))
	} else {
		caps.Details = append(caps.Details, fmt.Sprintf("Linux Landlock LSM probe: unavailable (%v)", err))
	}

	return caps
}

func preparePlatformCommand(_ policy.SandboxPolicy, name string, args []string) (string, []string, []string, []string) {
	return name, args, nil, nil
}

func configurePlatformProcess(wc *WrappedCmd) error {
	wc.Cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	wc.Cmd.WaitDelay = 3 * time.Second
	wc.ActiveControls = append(wc.ActiveControls, "posix_pgid")

	if wc.Cfg.UseLandlock {
		if abi, err := probeLandlockABI(); err == nil && abi > 0 {
			wc.ActiveControls = append(wc.ActiveControls, fmt.Sprintf("landlock_abi_v%d_detected", abi))
		}
	}

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
