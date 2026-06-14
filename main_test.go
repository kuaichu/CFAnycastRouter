package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestWaitForNextCycleContinuesAfterInterval(t *testing.T) {
	control := newRunControl(false)
	exitCh := make(chan struct{})
	if !waitForNextCycle(time.Millisecond, control, exitCh) {
		t.Fatal("expected wait to continue after interval")
	}
}

func TestWaitForNextCyclePausesAndResumes(t *testing.T) {
	control := newRunControl(false)
	exitCh := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		done <- waitForNextCycle(time.Hour, control, exitCh)
	}()

	control.stop()
	select {
	case <-done:
		t.Fatal("wait returned while paused")
	case <-time.After(20 * time.Millisecond):
	}

	control.start()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("expected wait to continue after resume")
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not resume")
	}
}

func TestPauseIgnoresStaleResumeSignal(t *testing.T) {
	control := newRunControl(false)
	exitCh := make(chan struct{})
	control.stop()
	control.start()
	control.stop()

	done := make(chan bool, 1)
	go func() {
		done <- waitIfPaused(control, exitCh)
	}()

	select {
	case <-done:
		t.Fatal("pause was released by a stale resume signal")
	case <-time.After(20 * time.Millisecond):
	}

	control.start()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("expected wait to continue after fresh resume")
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not resume")
	}
}

func TestWaitForNextCycleStopsOnExit(t *testing.T) {
	control := newRunControl(false)
	exitCh := make(chan struct{}, 1)
	exitCh <- struct{}{}
	if waitForNextCycle(time.Hour, control, exitCh) {
		t.Fatal("expected wait to stop after exit request")
	}
}

func TestAutoScanPauseStatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auto-scan-paused")
	if loadAutoScanPaused(path) {
		t.Fatal("pause marker should not exist yet")
	}
	if err := setAutoScanPaused(path, true); err != nil {
		t.Fatalf("pause failed: %v", err)
	}
	if !loadAutoScanPaused(path) {
		t.Fatal("pause marker was not saved")
	}
	if err := setAutoScanPaused(path, false); err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if loadAutoScanPaused(path) {
		t.Fatal("pause marker should be removed after resume")
	}
}
