//go:build windows

package sandbox

import (
	"fmt"
	"syscall"
	"testing"
)

func TestIsNestedJobDeniedDetection(t *testing.T) {
	if !isNestedJobDenied(syscall.ERROR_ACCESS_DENIED) {
		t.Fatalf("expected syscall.ERROR_ACCESS_DENIED to be recognized as nested-job denial")
	}
	wrapped := fmt.Errorf("assign failed: %w", syscall.ERROR_ACCESS_DENIED)
	if !isNestedJobDenied(wrapped) {
		t.Fatalf("expected wrapped ERROR_ACCESS_DENIED to be recognized")
	}
	if isNestedJobDenied(syscall.EINVAL) {
		t.Fatalf("did not expect EINVAL to match nested-job denial")
	}
}
