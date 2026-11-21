//go:build windows

package sandbox

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/aloneangel45/mcpgate/pkg/policy"
)

const (
	jobObjectExtendedLimitInformation = 9

	jobObjectLimitActiveProcess  = 0x00000008
	jobObjectLimitJobMemory      = 0x00000200
	jobObjectLimitKillOnJobClose = 0x00002000

	processSetQuota  = 0x0100
	processTerminate = 0x0001
	processQueryInfo = 0x0400

	stillActiveExitCode = 259
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW     = kernel32.NewProc("CreateJobObjectW")
	procSetInfoJobObject     = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob   = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject   = kernel32.NewProc("TerminateJobObject")
	procGetExitCodeProcess   = kernel32.NewProc("GetExitCodeProcess")
)

// ioCounters matches Win32 IO_COUNTERS.
type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// jobObjectBasicLimitInformation matches Win32 JOBOBJECT_BASIC_LIMIT_INFORMATION.
type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

// jobObjectExtendedLimitInfo matches Win32 JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func platformCapabilities() HostCapabilities {
	caps := HostCapabilities{
		OS:                   runtime.GOOS,
		Arch:                 runtime.GOARCH,
		ProcessIsolation:     "Win32 Job Object",
		CleanEnvSupported:    true,
		FilesystemJail:       "Policy Path Guard + Win32 Job",
		MemoryLimitSupported: true,
		Details: []string{
			"Win32 Job Object enforces JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE for descendant cleanup",
			"Supports JOB_OBJECT_LIMIT_JOB_MEMORY and JOB_OBJECT_LIMIT_ACTIVE_PROCESS caps",
		},
	}
	if err := probeJobObjectSupport(); err != nil {
		caps.Details = append(caps.Details, fmt.Sprintf("Job Object probe warning: %v", err))
		caps.MemoryLimitSupported = false
	}
	return caps
}

func probeJobObjectSupport() error {
	h, err := createJobObject()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)

	var info jobObjectExtendedLimitInfo
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	return setJobObjectLimits(h, &info)
}

func preparePlatformCommand(_ policy.SandboxPolicy, name string, args []string) (string, []string, []string, []string) {
	return name, args, nil, nil
}

func configurePlatformProcess(wc *WrappedCmd) error {
	jobHandle, err := createJobObject()
	if err != nil {
		return fmt.Errorf("sandbox: create Win32 job object: %w", err)
	}

	var info jobObjectExtendedLimitInfo
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	controls := []string{"win32_job_object"}

	if wc.Cfg.MaxProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= jobObjectLimitActiveProcess
		info.BasicLimitInformation.ActiveProcessLimit = uint32(wc.Cfg.MaxProcesses)
		controls = append(controls, fmt.Sprintf("max_processes=%d", wc.Cfg.MaxProcesses))
	}
	if wc.Cfg.MaxMemoryMB > 0 {
		memBytes := uint64(wc.Cfg.MaxMemoryMB) * 1024 * 1024
		maxUintptr := uint64(^uintptr(0))
		if memBytes > maxUintptr {
			memBytes = maxUintptr
		}
		info.BasicLimitInformation.LimitFlags |= jobObjectLimitJobMemory
		info.JobMemoryLimit = uintptr(memBytes)
		controls = append(controls, fmt.Sprintf("max_memory_mb=%d", wc.Cfg.MaxMemoryMB))
	}

	if err := setJobObjectLimits(jobHandle, &info); err != nil {
		_ = syscall.CloseHandle(jobHandle)
		return fmt.Errorf("sandbox: configure Win32 job object limits: %w", err)
	}

	wc.ActiveControls = append(wc.ActiveControls, controls...)

	var jobMu sync.Mutex
	closed := false

	wc.onStart = func() error {
		if wc.Cmd == nil || wc.Cmd.Process == nil {
			return fmt.Errorf("sandbox: missing child process after start")
		}
		jobMu.Lock()
		defer jobMu.Unlock()
		if closed || jobHandle == 0 {
			return fmt.Errorf("sandbox: job object already closed")
		}

		pid := uint32(wc.Cmd.Process.Pid)
		procHandle, err := syscall.OpenProcess(processSetQuota|processTerminate|processQueryInfo, false, pid)
		if err != nil {
			return fmt.Errorf("sandbox: open child process %d for job assignment: %w", pid, err)
		}
		defer syscall.CloseHandle(procHandle)

		if err := assignProcessToJobObject(jobHandle, procHandle); err != nil {
			// If the child exited almost instantaneously before assignment, allow clean exit.
			if exited, _ := processHasExited(procHandle); exited {
				return nil
			}
			return fmt.Errorf("sandbox: assign process %d to Win32 job object: %w", pid, err)
		}
		return nil
	}

	wc.onKill = func() error {
		jobMu.Lock()
		defer jobMu.Unlock()
		if closed || jobHandle == 0 {
			return nil
		}
		return terminateJobObject(jobHandle, 1)
	}

	wc.onCleanup = func() error {
		jobMu.Lock()
		defer jobMu.Unlock()
		if closed || jobHandle == 0 {
			return nil
		}
		closed = true
		h := jobHandle
		jobHandle = 0
		return syscall.CloseHandle(h)
	}

	return nil
}

func createJobObject() (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return 0, err
		}
		return 0, fmt.Errorf("CreateJobObjectW returned NULL")
	}
	return syscall.Handle(r1), nil
}

func setJobObjectLimits(job syscall.Handle, info *jobObjectExtendedLimitInfo) error {
	r1, _, err := procSetInfoJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(info)),
		unsafe.Sizeof(*info),
	)
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("SetInformationJobObject failed")
	}
	return nil
}

func assignProcessToJobObject(job, proc syscall.Handle) error {
	r1, _, err := procAssignProcessToJob.Call(uintptr(job), uintptr(proc))
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("AssignProcessToJobObject failed")
	}
	return nil
}

func terminateJobObject(job syscall.Handle, exitCode uint32) error {
	r1, _, err := procTerminateJobObject.Call(uintptr(job), uintptr(exitCode))
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return err
		}
		return fmt.Errorf("TerminateJobObject failed")
	}
	return nil
}

func processHasExited(proc syscall.Handle) (bool, error) {
	var code uint32
	r1, _, err := procGetExitCodeProcess.Call(uintptr(proc), uintptr(unsafe.Pointer(&code)))
	if r1 == 0 {
		if err != nil && err != syscall.Errno(0) {
			return false, err
		}
		return false, fmt.Errorf("GetExitCodeProcess failed")
	}
	return code != stillActiveExitCode, nil
}
