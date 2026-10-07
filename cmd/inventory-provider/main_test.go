package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestProviderOwnsOnlyExplicitFileCatalogers(t *testing.T) {
	cfg := providerConfig()
	if cfg.DataGeneration.GenerateCPEs || len(cfg.CatalogerSelection.DefaultNamesOrTags) != 10 ||
		len(cfg.CatalogerSelection.SubSelectTags) != 0 || len(cfg.CatalogerSelection.AddNames) != 0 ||
		len(cfg.CatalogerSelection.RemoveNamesOrTags) != 0 {
		t.Fatal("provider selection widened")
	}
	for _, name := range cfg.CatalogerSelection.DefaultNamesOrTags {
		if name == "directory" || name == "python-package-cataloger" {
			t.Fatal("unrestricted provider selection")
		}
	}
	root := t.TempDir()
	files := map[string]string{
		"requirements.txt":  "pip==26.0.1\n",
		"package-lock.json": `{"name":"fixture","lockfileVersion":3,"packages":{"node_modules/debug":{"version":"4.3.7","dependencies":{"ms":"^2.1.3"}},"node_modules/ms":{"version":"2.1.3"}}}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runProvider(context.Background(), root, &output, maxOutput); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	artifacts := document["artifacts"].([]any)
	if len(artifacts) != 2 {
		t.Fatalf("provider admitted Python declarations or lost locks: %d", len(artifacts))
	}
	for _, raw := range artifacts {
		artifact := raw.(map[string]any)
		if artifact["foundBy"] != "javascript-lock-cataloger" || artifact["type"] != "npm" || len(artifact["cpes"].([]any)) != 0 {
			t.Fatalf("unexpected provider: %v", artifact)
		}
	}
}

func TestProviderRetainsInstalledPythonSeparately(t *testing.T) {
	root := t.TempDir()
	metadata := filepath.Join(root, "site-packages", "pip-26.0.1.dist-info")
	if err := os.MkdirAll(metadata, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		filepath.Join(root, "requirements.txt"): "pip==99.99.99\n",
		filepath.Join(metadata, "METADATA"):     "Metadata-Version: 2.3\nName: pip\nVersion: 26.0.1\nRequires-Dist: packaging>=24\n\n",
		filepath.Join(metadata, "RECORD"):       "",
	} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	if err := runProvider(context.Background(), root, &output, maxOutput); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	artifacts := document["artifacts"].([]any)
	if len(artifacts) != 1 {
		t.Fatalf("expected installed evidence only, got%d", len(artifacts))
	}
	artifact := artifacts[0].(map[string]any)
	if artifact["foundBy"] != "python-installed-package-cataloger" || artifact["purl"] != "pkg:pypi/pip@26.0.1" {
		t.Fatalf("lost installed identity: %v", artifact)
	}
}

func TestProfileDisablesKnownExecutionAndEnrichment(t *testing.T) {
	cfg := providerConfig()
	p := cfg.Packages
	if cfg.DataGeneration.GenerateCPEs || cfg.Parallelism != 2 || p.Golang.UsePackagesLib || p.Golang.SearchRemoteLicenses || p.Golang.SearchLocalModCacheLicenses || p.Golang.SearchLocalVendorLicenses || p.Python.SearchRemoteLicenses || p.Python.GuessUnpinnedRequirements || p.JavaScript.SearchRemoteLicenses || !p.JavaScript.IncludeDevDependencies || p.JavaArchive.UseNetwork || p.JavaArchive.UseMavenLocalRepository || p.JavaArchive.ResolveTransitiveDependencies || p.Cpp.VcpkgAllowGitClone {
		t.Fatal("restricted profile widened")
	}
}

func TestRefusalsNeverEmitPartialEvidence(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{"", "relative", link, filepath.Join(root, "missing")} {
		var output bytes.Buffer
		if err := runProvider(context.Background(), input, &output, maxOutput); err == nil || output.Len() != 0 {
			t.Fatal("invalid root admitted or output emitted")
		}
	}
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runProvider(ctx, root, &output, maxOutput); err == nil || output.Len() != 0 {
		t.Fatal("cancellation admitted")
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"example","version":"1.0.0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runProvider(context.Background(), root, &output, 1); err == nil || output.Len() != 0 {
		t.Fatal("bounded output admitted")
	}
}
