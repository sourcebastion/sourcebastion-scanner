package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func envelope() map[string]any {
	dimensions := map[string]any{}
	for _, name := range []string{"inputs", "occurrences", "relationships", "declaration_records", "references", "roots", "applications", "environment_records"} {
		dimensions[name] = []any{}
	}
	fidelity := map[string]any{}
	for _, name := range []string{"discovery", "parsing", "enumeration", "version_selection", "graph", "environment"} {
		fidelity[name] = "complete"
	}
	fidelity["graph"] = "unknown"
	fidelity["environment"] = "unconditional"
	dimensions["fidelity"] = fidelity
	return map[string]any{"schema_version": "m046-static-inventory-prototype-v5", "inventory_status": "complete",
		"sbom_status": "not-run", "matching_status": "not-run", "coverage": "prototype-static-python",
		"packages": []any{}, "edges": []any{}, "application_identities": []any{}, "refusal_codes": []any{}, "semantic_dimensions": dimensions}
}

func TestProtocolRequiresEveryDimension(t *testing.T) {
	content, _ := json.Marshal(envelope())
	if _, err := decodeFrontend(context.Background(), content); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"semantic_dimensions", "packages", "edges", "coverage"} {
		doc := envelope()
		delete(doc, field)
		content, _ := json.Marshal(doc)
		if _, err := decodeFrontend(context.Background(), content); err == nil {
			t.Fatal("accepted missing", field)
		}
	}
	for _, field := range []string{"inputs", "occurrences", "relationships", "declaration_records", "references", "roots", "applications", "environment_records", "fidelity"} {
		doc := envelope()
		delete(doc["semantic_dimensions"].(map[string]any), field)
		content, _ := json.Marshal(doc)
		if _, err := decodeFrontend(context.Background(), content); err == nil {
			t.Fatal("accepted missing dimension", field)
		}
	}
	for _, raw := range []string{`{"schema_version":"v5","schema_version":"v5"}`, string(content) + "{}", strings.Repeat("[", 34) + strings.Repeat("]", 34)} {
		if _, err := decodeFrontend(context.Background(), []byte(raw)); err == nil {
			t.Fatal("accepted invalid JSON shape")
		}
	}
}

func TestMalformedOccurrencesRefuseBeforeProjection(t *testing.T) {
	for _, edit := range []func(map[string]any){
		func(r map[string]any) { r["package"] = "pypi:foo@>=1" },
		func(r map[string]any) { r["path"] = "/etc/secret" },
		func(r map[string]any) { r["path"] = "../secret" },
		func(r map[string]any) { r["root"] = false },
		func(r map[string]any) { r["marker"] = 12 },
		func(r map[string]any) { r["extras"] = map[string]any{} },
		func(r map[string]any) { r["selection"] = "installed-guessed" },
	} {
		r := selected(".", "requirements.txt", "line:1", "pypi:foo@1")
		edit(r)
		doc := frontendDocument{}
		doc.Dimensions.Occurrences = []map[string]any{r}
		if _, _, _, err := project(context.Background(), doc); err == nil {
			t.Fatal("accepted malformed occurrence", r)
		}
	}
}

func TestProtocolRejectsContradictoryRichSidecar(t *testing.T) {
	for _, edit := range []func(map[string]any){
		func(d map[string]any) { d["semantic_dimensions"].(map[string]any)["inputs"] = []any{true} },
		func(d map[string]any) {
			d["semantic_dimensions"].(map[string]any)["fidelity"].(map[string]any)["parsing"] = "invented-complete"
		},
		func(d map[string]any) { d["edges"] = []any{[]string{"pypi:foo@1", "pypi:bar@1"}} },
		func(d map[string]any) { d["application_identities"] = []any{"pypi:phantom@1"} },
		func(d map[string]any) { d["semantic_dimensions"].(map[string]any)["environment_records"] = []any{true} },
		func(d map[string]any) { d["semantic_dimensions"].(map[string]any)["references"] = []any{true} },
	} {
		doc := envelope()
		edit(doc)
		content, _ := json.Marshal(doc)
		if _, err := decodeFrontend(context.Background(), content); err == nil {
			t.Fatal("accepted contradictory rich sidecar", doc)
		}
	}
	doc := envelope()
	dimensions := doc["semantic_dimensions"].(map[string]any)
	dimensions["roots"] = []any{"."}
	dimensions["inputs"] = []any{map[string]any{
		"path": "script.py.lock", "format": "uv-script-lock", "sha256": nil, "roots": []any{"."},
		"disposition": "unsupported", "reason": "parser-not-implemented"}}
	content, _ := json.Marshal(doc)
	if _, err := decodeFrontend(context.Background(), content); err == nil {
		t.Fatal("accepted complete unsupported input")
	}
	doc["inventory_status"] = "partial"
	fidelity := dimensions["fidelity"].(map[string]any)
	for _, field := range []string{"parsing", "enumeration", "version_selection"} {
		fidelity[field] = "partial"
	}
	fidelity["environment"] = "unknown"
	content, _ = json.Marshal(doc)
	if _, err := decodeFrontend(context.Background(), content); err != nil {
		t.Fatal("refused explicit partial unsupported input", err)
	}
}

func TestOccurrenceRootMustBelongToItsOwnInput(t *testing.T) {
	doc := envelope()
	dimensions := doc["semantic_dimensions"].(map[string]any)
	dimensions["roots"] = []any{".", "other"}
	dimensions["inputs"] = []any{
		map[string]any{"path": "uv.lock", "format": "uv-lock", "sha256": strings.Repeat("a", 64), "roots": []any{"."}, "disposition": "parsed", "reason": "static-input"},
		map[string]any{"path": "other/file", "format": "unrecognized", "sha256": nil, "roots": []any{"other"}, "disposition": "ignored", "reason": "unrecognized-input"},
	}
	occurrence := selected(".", "uv.lock", "package[0]", "pypi:foo@1")
	dimensions["occurrences"] = []any{occurrence}
	doc["packages"] = []any{"pypi:foo@1"}
	dimensions["fidelity"].(map[string]any)["environment"] = "conditional-unknown"
	content, _ := json.Marshal(doc)
	if _, err := decodeFrontend(context.Background(), content); err != nil {
		t.Fatal("refused valid input roots", err)
	}
	occurrence["root"] = "other"
	content, _ = json.Marshal(doc)
	if _, err := decodeFrontend(context.Background(), content); err == nil {
		t.Fatal("borrowed another input root")
	}
}

func TestBindingAdmissionRejectsPackageAndRelationTampering(t *testing.T) {
	for _, edit := range []func(*pkg.Package){
		func(p *pkg.Package) { p.Version = "2" }, func(p *pkg.Package) { p.Name = "other" },
		func(p *pkg.Package) { p.PURL = "pkg:pypi/other@1" }, func(p *pkg.Package) { p.Type = pkg.NpmPkg },
		func(p *pkg.Package) {
			locations := p.Locations.ToSlice()
			locations[0].Annotations["m046:locator"] = "changed"
		},
	} {
		doc := frontendDocument{}
		doc.Dimensions.Occurrences = []map[string]any{selected(".", "uv.lock", "package[0]", "pypi:foo@1")}
		packages, _, _, err := project(context.Background(), doc)
		if err != nil {
			t.Fatal(err)
		}
		f := frontendCataloger{expectedPackages: map[string]string{string(packages[0].ID()): packageSignature(packages[0])}, expectedRelations: map[string]int{}}
		s := &sbom.SBOM{}
		s.Artifacts.Packages = pkg.NewCollection(packages...)
		if err := f.validateBindings(s); err != nil {
			t.Fatal(err)
		}
		edit(&packages[0])
		s.Artifacts.Packages = pkg.NewCollection(packages...)
		if err := f.validateBindings(s); err == nil {
			t.Fatal("accepted changed package")
		}
	}
	f := frontendCataloger{expectedPackages: map[string]string{}, expectedRelations: map[string]int{"required": 1}}
	s := &sbom.SBOM{}
	s.Artifacts.Packages = pkg.NewCollection()
	if err := f.validateBindings(s); err == nil {
		t.Fatal("accepted lost relationship")
	}
}

func TestPipeWriterHelper(t *testing.T) {
	mode := os.Getenv("M046_PIPE_MODE")
	if mode == "" {
		return
	}
	if mode == "sleep" {
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	writer := io.Writer(os.Stdout)
	if mode == "stderr" {
		writer = os.Stderr
	}
	fmt.Fprint(writer, strings.Repeat("x", 128*1024))
	os.Exit(0)
}

func TestRealProcessPipeIsBoundedAndCancelled(t *testing.T) {
	for _, mode := range []string{"stdout", "stderr", "sleep"} {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if mode == "sleep" {
			cancel()
			ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPipeWriterHelper$")
		cmd.Env = []string{"M046_PIPE_MODE=" + mode}
		cmd.WaitDelay = time.Second
		b := &boundedBuffer{limit: 1024, ctx: ctx}
		if mode == "stderr" {
			cmd.Stderr = b
		} else {
			cmd.Stdout = b
		}
		err := cmd.Run()
		cancel()
		if err == nil || b.Len() > 1024 {
			t.Fatal("pipe overflow/cancellation accepted", mode, err, b.Len())
		}
	}
}

func TestMixedInstalledScriptAndDeclaredInputs(t *testing.T) {
	python := os.Getenv("M046_FRONTEND_PYTHON")
	if python == "" {
		t.Skip("trusted frontend interpreter supplied only by explicit evaluator preparation")
	}
	cli, err := filepath.Abs("../static_cli.py")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("pip==26.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(root, "pip-26.0.1.dist-info")
	if err := os.Mkdir(metadata, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(metadata, "METADATA"), []byte("Metadata-Version: 2.1\nName: pip\nVersion: 26.0.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "script.py.lock"), []byte("version = 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := runExtended(ctx, root, python, cli, false, &output); err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal([]byte(output.String()), &bundle); err != nil {
		t.Fatal(err)
	}
	sidecar := bundle["sidecar"].(map[string]any)
	inventory := sidecar["inventory"].(map[string]any)
	if inventory["inventory_status"] != "partial" || sidecar["whole_repository_coverage"] != "unknown" {
		t.Fatal("claimed complete", sidecar)
	}
	artifacts := bundle["syft"].(map[string]any)["artifacts"].([]any)
	if len(artifacts) != 2 {
		t.Fatal("installed/declared occurrence lost", len(artifacts))
	}
	ids := map[string]bool{}
	found := map[string]bool{}
	for _, raw := range artifacts {
		p := raw.(map[string]any)
		ids[p["id"].(string)] = true
		found[p["foundBy"].(string)] = true
	}
	if len(ids) != 2 || !found[catalogerName] || !found["python-installed-package-cataloger"] {
		t.Fatal(ids, found)
	}
}

func TestRealFrontendCorpusProtocol(t *testing.T) {
	python := os.Getenv("M046_FRONTEND_PYTHON")
	if python == "" {
		t.Skip("trusted frontend interpreter required")
	}
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	// Only the built-in synthetic corpus and trusted frontend execute. No
	// project setup script or package manager runs in this preparation test.
	script := `import json,sys,tempfile
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from evaluation.m046.corpus import CORPUS
from evaluation.m046.run import materialize
from evaluation.m046.static_inputs import Source
from evaluation.m046.static_inventory import evaluate
records=[]
with tempfile.TemporaryDirectory(prefix="m046-protocol-corpus-") as temporary:
 for fixture in CORPUS:
  root=Path(temporary)/fixture["id"]/"source"
  materialize(fixture,root)
  with Source(root) as source:
   records.append({"fixture":fixture["id"],"document":evaluate(source)})
print(json.dumps(records))
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-I", "-B", "-c", script, repo)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("trusted corpus frontend: %v", err)
	}
	var records []struct {
		Fixture  string          `json:"fixture"`
		Document json.RawMessage `json:"document"`
	}
	if err := json.Unmarshal(output, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 64 {
		t.Fatal("unexpected corpus count", len(records))
	}
	for _, record := range records {
		t.Run(record.Fixture, func(t *testing.T) {
			if _, err := decodeFrontend(ctx, record.Document); err != nil {
				t.Fatal(err)
			}
		})
	}
}
