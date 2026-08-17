package main

import (
	"strings"
	"testing"
)

func TestResumeCommandRequiresExplicitConfirmation(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"resume", "--zone", "example.test", "--idempotency-key", "resume-cli-test-0001"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestResumeCommandIsPresent(t *testing.T) {
	cmd, _, err := root().Find([]string{"resume"})
	if err != nil || cmd == nil || cmd.Name() != "resume" {
		t.Fatalf("command=%v error=%v", cmd, err)
	}
}

func TestReconcileSplitSignerCommandRequiresExplicitConfirmation(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"reconcile-split-signer", "--zone", "example.test", "--idempotency-key", "signer-cli-test-0001"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestReconcileSplitSignerCommandIsPresent(t *testing.T) {
	cmd, _, err := root().Find([]string{"reconcile-split-signer"})
	if err != nil || cmd == nil || cmd.Name() != "reconcile-split-signer" {
		t.Fatalf("command=%v error=%v", cmd, err)
	}
}

func TestEnrollmentArmRequiresExplicitConfirmation(t *testing.T) {
	cmd := root()
	cmd.SetArgs([]string{"enrollment", "arm", "--idempotency-key", "enrollment-arm-test-0001"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("error=%v", err)
	}
}
