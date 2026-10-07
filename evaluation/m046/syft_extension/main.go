// Controlled M046 library experiment. This binary is not a scan isolation boundary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/sbom"
	_ "modernc.org/sqlite" // Syft RPM and Nix database readers.
)

const maxOutput = 64 * 1024 * 1024

var errOutputLimit = errors.New("syft-output-budget-exceeded")

// Prepare the entire document before stdout. Model conversion itself needs the
// outer job memory limit; a writer limit alone does not bound allocation.
type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
	ctx    context.Context
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > b.limit-b.Len() {
		return 0, errOutputLimit
	}
	return b.buffer.Write(p)
}

func (b *boundedBuffer) Len() int       { return b.buffer.Len() }
func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }

// Identical explicit profile for both CPE arms. This is a library profile, not
// assumed parity with the stock CLI. Process/network denial needs an outer
// boundary and traces. GOPROXY=off alone is NOT a Syft kill switch.
func controlConfig(cpes bool) *syft.CreateSBOMConfig {
	goCfg := golang.DefaultCatalogerConfig().
		WithUsePackagesLib(false).
		WithSearchLocalModCacheLicenses(false).
		WithSearchLocalVendorLicenses(false).
		WithSearchRemoteLicenses(false)
	goCfg.LocalModCacheDir = ""
	goCfg.Proxies = nil
	goCfg.NoProxy = nil
	packages := pkgcataloging.DefaultConfig().
		WithGolangConfig(goCfg).
		WithPythonConfig(python.DefaultCatalogerConfig().
			WithSearchRemoteLicenses(false).WithGuessUnpinnedRequirements(false)).
		WithJavascriptConfig(javascript.DefaultCatalogerConfig().
			WithSearchRemoteLicenses(false).WithIncludeDevDependencies(true)).
		WithJavaArchiveConfig(java.DefaultArchiveCatalogerConfig().
			WithUseNetwork(false).WithUseMavenLocalRepository(false).
			WithResolveTransitiveDependencies(false)).
		WithCppConfig(cpp.DefaultCatalogerConfig().WithVcpkgAllowGitClone(false))
	return syft.DefaultCreateSBOMConfig().
		WithParallelism(2).
		WithComplianceConfig(cataloging.ComplianceConfig{MissingName: cataloging.ComplianceActionDrop, MissingVersion: cataloging.ComplianceActionKeep}).
		WithPackagesConfig(packages).
		WithDataGenerationConfig(cataloging.DefaultDataGenerationConfig().WithGenerateCPEs(cpes)).
		WithTool("m046-syft-library-control", "v1", map[string]any{
			"syft": "1.54.0", "profile": "offline-library-v1", "generate_cpes": cpes,
		})
}

// The provider is deliberately separate from both historical CPE controls and
// the Go-to-Python extension. No Python declaration cataloger owns source files.
var providerCatalogers = []string{
	"javascript-lock-cataloger", "javascript-package-cataloger",
	"go-module-file-cataloger", "rust-cargo-lock-cataloger",
	"python-installed-package-cataloger", "java-gradle-lockfile-cataloger",
	"java-pom-cataloger", "dotnet-packages-lock-cataloger",
	"ruby-gemfile-cataloger", "php-composer-lock-cataloger",
}

func providerConfig() *syft.CreateSBOMConfig {
	return controlConfig(false).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(providerCatalogers...)).
		WithTool("m046-restricted-evidence-provider", "v1", map[string]any{
			"syft": "1.54.0", "profile": "offline-file-provider-v1", "generate_cpes": false,
			"catalogers": providerCatalogers, "coverage": "unassessed",
		})
}

func runProvider(ctx context.Context, root string, output io.Writer) error {
	document, err := create(ctx, root, providerConfig())
	if err != nil {
		return err
	}
	buffer := &boundedBuffer{limit: maxOutput, ctx: ctx}
	if err := syftjson.NewFormatEncoder().Encode(buffer, *document); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = output.Write(buffer.Bytes())
	return err
}

func create(ctx context.Context, root string, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute-root-required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("directory-root-required")
	}
	// Explicit directory provider prevents registry/image auto detection.
	src, err := syft.GetSource(ctx, root, syft.DefaultGetSourceConfig().WithSources("dir"))
	if err != nil {
		return nil, fmt.Errorf("directory-source: %w", err)
	}
	defer src.Close()
	document, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, fmt.Errorf("syft-catalog: %w", err)
	}
	return document, nil
}

func run(ctx context.Context, root string, cpes bool, output io.Writer) error {
	document, err := create(ctx, root, controlConfig(cpes))
	if err != nil {
		return err
	}
	buffer := &boundedBuffer{limit: maxOutput, ctx: ctx}
	if err := syftjson.NewFormatEncoder().Encode(buffer, *document); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = output.Write(buffer.Bytes())
	return err
}

func runExtended(ctx context.Context, root, python, cli string, cpes bool, output io.Writer) error {
	frontend := &frontendCataloger{root: root, python: python, cli: cli}
	cfg := controlConfig(cpes).
		WithCatalogerSelection(cataloging.NewSelectionRequest().
			WithRemovals("python-package-cataloger").WithAdditions("python-installed-package-cataloger")).
		WithCatalogers(pkgcataloging.NewAlwaysEnabledCatalogerReference(frontend)).
		WithTool("m046-extended-syft", "v1", map[string]any{
			"syft": "1.54.0", "profile": "offline-library-v1", "generate_cpes": cpes,
			"frontend": "m046-static-inventory-prototype-v5", "graph": "informational-only",
		})
	document, err := create(ctx, root, cfg)
	if err != nil {
		return err
	}
	if len(frontend.inventory) == 0 {
		return errors.New("missing-static-frontend-result")
	}
	if err := frontend.validateBindings(document); err != nil {
		return err
	}
	// Each retained inventory sidecar / Syft serialization has its own 64MiB
	// ceiling. The wrapper is an evaluation bundle, not a standard SBOM.
	sidecar := &boundedBuffer{limit: maxOutput, ctx: ctx}
	if err := json.NewEncoder(sidecar).Encode(map[string]any{
		"inventory": frontend.inventory, "projection": frontend.projection,
		"whole_repository_coverage": "unknown", "matching_status": "not-run",
		"projection_losses": []string{"unselected-declarations-not-match-packages", "rich-context-authoritative-in-sidecar", "informational-relations-not-standard-dependencies", "stock-ecosystem-fidelity-uncharacterized", "cyclonedx-spdx-roundtrip-unproved", "grype-consumer-compatibility-unproved"},
	}); err != nil {
		return err
	}
	syftJSON := &boundedBuffer{limit: maxOutput, ctx: ctx}
	if err := syftjson.NewFormatEncoder().Encode(syftJSON, *document); err != nil {
		return err
	}
	bundle := &boundedBuffer{limit: 2*maxOutput + 4096, ctx: ctx}
	if err := json.NewEncoder(bundle).Encode(map[string]any{
		"schema_version": "m046-extended-syft-evaluation-v1",
		"sidecar":        json.RawMessage(sidecar.Bytes()), "syft": json.RawMessage(syftJSON.Bytes()),
	}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = output.Write(bundle.Bytes())
	return err
}

func main() {
	root := flag.String("root", "", "absolute read-only synthetic source directory")
	mode := flag.String("mode", "control", "control, extended or provider evaluation mode")
	python := flag.String("python", "", "trusted absolute Python executable (extended mode)")
	frontend := flag.String("frontend", "", "trusted absolute static_cli.py (extended mode)")
	cpes := flag.Bool("generate-cpes", true, "only experimental variable in the library control")
	timeout := flag.Duration("timeout", 150*time.Second, "clamp to remaining outer job deadline (max 150s)")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > 150*time.Second ||
		(*mode != "control" && *mode != "extended" && *mode != "provider") ||
		(*mode != "extended" && (*python != "" || *frontend != "")) ||
		(*mode == "extended" && (*python == "" || *frontend == "")) {
		fmt.Fprintln(os.Stderr, "invalid-evaluation-arguments")
		os.Exit(2)
	}
	ctx, cancelSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelSignal()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var err error
	if *mode == "control" {
		err = run(ctx, *root, *cpes, os.Stdout)
	} else if *mode == "provider" {
		err = runProvider(ctx, *root, os.Stdout)
	} else {
		err = runExtended(ctx, *root, *python, *frontend, *cpes, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
