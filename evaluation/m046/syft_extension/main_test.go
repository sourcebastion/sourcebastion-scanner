package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestControlOnlyChangesCPEGeneration(t *testing.T) {
	on, off := controlConfig(true), controlConfig(false)
	if !on.DataGeneration.GenerateCPEs || off.DataGeneration.GenerateCPEs {
		t.Fatal("CPE arms not configured")
	}
	on.DataGeneration = off.DataGeneration
	on.ToolConfiguration = off.ToolConfiguration
	// Private task factories contain function pointers. All public, effective
	// control values are compared explicitly rather than comparing those funcs.
	a, err := json.Marshal(on)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(off)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("control profiles differ: %s / %s (%v)", a, b, err)
	}
	packages := on.Packages
	if packages.Golang.UsePackagesLib || packages.Golang.SearchRemoteLicenses ||
		packages.Golang.SearchLocalModCacheLicenses || packages.Golang.SearchLocalVendorLicenses ||
		packages.Python.SearchRemoteLicenses || packages.Python.GuessUnpinnedRequirements ||
		packages.JavaScript.SearchRemoteLicenses || packages.JavaArchive.UseNetwork ||
		packages.JavaArchive.UseMavenLocalRepository || packages.JavaArchive.ResolveTransitiveDependencies ||
		packages.Cpp.VcpkgAllowGitClone {
		t.Fatal("offline profile enables execution/enrichment")
	}
}

func TestBoundedBufferIsAtomicAtLimit(t *testing.T) {
	b := &boundedBuffer{limit: 3, ctx: context.Background()}
	if n, err := b.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := b.Write([]byte("d")); n != 0 || !errors.Is(err, errOutputLimit) {
		t.Fatal(n, err)
	}
	if b.String() != "abc" {
		t.Fatal("partial overflow retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.ctx = ctx
	if n, err := b.Write(nil); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal(n, err)
	}
}

func TestCopyCannotBypassBoundedWrite(t *testing.T) {
	b := &boundedBuffer{limit: 3, ctx: context.Background()}
	n, err := io.Copy(b, io.LimitReader(strings.NewReader("abcdef"), 6))
	if n != 0 || !errors.Is(err, errOutputLimit) || b.Len() != 0 {
		t.Fatal(n, err, b.Len())
	}
}

func TestRefusedRootEmitsNothing(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "relative", link, filepath.Join(root, "missing")} {
		var output bytes.Buffer
		if err := run(context.Background(), input, false, &output); err == nil {
			t.Fatalf("accepted %q", input)
		}
		if output.Len() != 0 {
			t.Fatal("refusal emitted output")
		}
	}
}

func TestSameLibraryCPEControlRetainsInventory(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("pip==26.0.1\nflask==2.0.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var results [2]map[string]any
	var cpeCount [2]int
	for i, enabled := range []bool{false, true} {
		var output bytes.Buffer
		if err := run(context.Background(), root, enabled, &output); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(output.Bytes(), &results[i]); err != nil {
			t.Fatal(err)
		}
		artifacts := results[i]["artifacts"].([]any)
		if len(artifacts) != 2 {
			t.Fatalf("expected2packages,got%d", len(artifacts))
		}
		for _, raw := range artifacts {
			p := raw.(map[string]any)
			if cpes, ok := p["cpes"].([]any); ok {
				cpeCount[i] += len(cpes)
			}
			delete(p, "cpes")
		}
		// Tool config necessarily records the experimental variable.
		delete(results[i], "descriptor")
	}
	if cpeCount[0] != 0 || cpeCount[1] == 0 {
		t.Fatalf("not an effective CPE control: %v", cpeCount)
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatal("CPE control changed non-CPE inventory")
	}
}
