package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

func TestQuotedRequirementsRemainMinimumObservations(t *testing.T) {
	input := []byte("module \"example.invalid/root\"\ngo 1.24\nrequire (\n \"example.invalid/alpha\" \"v1.2.3\" // indirect\n example.invalid/beta/v2 v2.0.0\n)\n")
	result, err := observe(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Requirements) != 2 || !result.Requirements[0].Indirect || result.Requirements[0].Line != 4 || result.Requirements[0].MinimumVersion != "v1.2.3" || result.SelectedVersions != "unreported" || result.Graph != "unreported" {
		t.Fatalf("incorrect source semantics: %+v", result)
	}
	r := result.Requirements[0]
	if !bytes.Contains(input[r.StartByte:r.EndByte], []byte("alpha")) {
		t.Fatal("source span not bound")
	}
}
func TestControlsAndDuplicateRequirementsRetained(t *testing.T) {
	input := []byte("module example.invalid/root\nrequire example.invalid/alpha v1.2.3\nrequire example.invalid/alpha v1.2.4\nreplace example.invalid/alpha => ../private\nexclude example.invalid/beta v1.0.0\ntoolchain go1.27.1\n")
	result, err := observe(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Requirements) != 2 || len(result.UnassessedDirectives) != 4 {
		t.Fatalf("dropped source controls: %+v", result)
	}
	raw, _ := json.Marshal(result)
	if bytes.Contains(raw, []byte("private")) {
		t.Fatal("local replacement path projected")
	}
}
func TestMalformedUnknownAndInvalidIdentitiesRefused(t *testing.T) {
	for _, input := range []string{"module example.invalid/root\nfuture secret\n", "module example.invalid/root\nrequire https://user:secret@example.invalid/pkg v1.2.3\n", "module example.invalid/root\nrequire example.invalid/pkg/v2 v1.2.3\n", "require example.invalid/pkg v1.2.3\n"} {
		result, err := observe([]byte(input))
		if err == nil || result != nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe malformed acceptance: %v", err)
		}
	}
}
func TestInputAndOutputBudgets(t *testing.T) {
	if result, err := observe(bytes.Repeat([]byte("a"), maxInput+1)); err == nil || result != nil {
		t.Fatal("oversized input accepted")
	}
	var output bytes.Buffer
	err := run(context.Background(), strings.NewReader("module example.invalid/root\n"), &output, 1)
	if err == nil || output.Len() != 0 {
		t.Fatal("output bound not atomic")
	}
}
func TestDeadlineCoversBlockedInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	var output bytes.Buffer
	if err := run(ctx, reader, &output, maxOutput); err == nil || output.Len() != 0 {
		t.Fatal("blocked input deadline not enforced")
	}
}

func TestDeadlineCoversBlockedOutput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := run(ctx, strings.NewReader("module example.invalid/root\n"), writer, maxOutput); err == nil {
		t.Fatal("blocked output deadline not enforced")
	}
}
