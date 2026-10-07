// Restricted file evidence provider. The controller owns input admission and
// the shared kernel/deadline boundary; this process is not an isolation sandbox.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	_ "modernc.org/sqlite"
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

func offlineConfig() *syft.CreateSBOMConfig {
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
		WithDataGenerationConfig(cataloging.DefaultDataGenerationConfig().WithGenerateCPEs(false)).
		WithTool("sourcebastion-offline-library", "1", map[string]any{
			"syft": "1.54.0", "profile": "offline-library-v1", "generate_cpes": false,
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
	return offlineConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(providerCatalogers...)).
		WithTool("sourcebastion-restricted-provider", "1", map[string]any{
			"syft": "1.54.0", "profile": "offline-file-provider-v1", "generate_cpes": false,
			"catalogers": providerCatalogers, "coverage": "unassessed",
		})
}

// root must be a controller-admitted snapshot. Syft reads are not Source's
// descriptor-relative reads, and these flags do not fence a hostile writer.
func runProvider(ctx context.Context, root string, output io.Writer, outputLimit int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !filepath.IsAbs(root) {
		return errors.New("absolute-root-required")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("directory-root-required")
	}
	if outputLimit < 1 || outputLimit > maxOutput {
		return errors.New("invalid-output-limit")
	}
	src, err := syft.GetSource(ctx, root, syft.DefaultGetSourceConfig().WithSources("dir"))
	if err != nil {
		return errors.New("provider-source-refused")
	}
	defer src.Close()
	document, err := syft.CreateSBOM(ctx, src, providerConfig())
	if err != nil {
		return errors.New("provider-catalog-failed")
	}
	if document.Artifacts.Packages.PackageCount() > 100000 || len(document.Relationships) > 500000 {
		return errors.New("provider-record-budget-exceeded")
	}
	buffer := &boundedBuffer{limit: outputLimit, ctx: ctx}
	if err := syftjson.NewFormatEncoder().Encode(buffer, *document); err != nil {
		return errors.New("provider-output-refused")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err = output.Write(buffer.Bytes())
	return err
}

func main() {
	runtime.GOMAXPROCS(2)
	arguments := flag.NewFlagSet("sourcebastion-inventory-provider", flag.ContinueOnError)
	arguments.SetOutput(io.Discard)
	root := arguments.String("root", "", "controller-admitted absolute source snapshot")
	remaining := arguments.Duration("remaining", 0, "remaining outer deadline; positive and at most 150s")
	limit := arguments.Int("output-bytes", maxOutput, "remaining bounded output; at most 64MiB")
	if arguments.Parse(os.Args[1:]) != nil || arguments.NArg() != 0 || *remaining <= 0 || *remaining > 150*time.Second || *limit < 1 || *limit > maxOutput {
		fmt.Fprintln(os.Stderr, "invalid-provider-arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *remaining)
	defer cancel()
	if err := runProvider(ctx, *root, os.Stdout, *limit); err != nil {
		// Library/source exceptions may contain customer paths or source text.
		// A fixed diagnostic does not publish raw provider errors.
		fmt.Fprintln(os.Stderr, "restricted-provider-failed")
		os.Exit(2)
	}
}
