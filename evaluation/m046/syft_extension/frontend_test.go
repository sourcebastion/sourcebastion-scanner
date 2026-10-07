package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func selected(root, path, locator, identity string) map[string]any {
	return map[string]any{"root": root, "path": path, "locator": locator, "package": identity,
		"scope": "unknown", "marker": nil, "extras": []any{}, "activation": "unknown",
		"selection": "locked", "relationship": "unknown", "requires_python": nil, "declared_range": nil, "hashes": []any{}}
}

func TestOccurrenceContextAndLocalVersionRetained(t *testing.T) {
	doc := frontendDocument{}
	base := selected("a", "a/uv.lock", "package[0]", "pypi:foo@1+local")
	doc.Dimensions.Occurrences = append(doc.Dimensions.Occurrences, base)
	for _, field := range []string{"root", "scope", "marker", "locator", "extras"} {
		copy := map[string]any{}
		for k, v := range base {
			copy[k] = v
		}
		if field == "extras" {
			copy[field] = []any{"test"}
		} else {
			copy[field] = "different"
		}
		doc.Dimensions.Occurrences = append(doc.Dimensions.Occurrences, copy)
	}
	pkgs, relations, result, err := project(context.Background(), doc)
	if err != nil || len(pkgs) != 6 || len(relations) != 0 || len(result.Occurrences) != 6 {
		t.Fatal(err, len(pkgs), result)
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		if seen[string(p.ID())] {
			t.Fatal("occurrence collapsed")
		}
		seen[string(p.ID())] = true
		if p.Version != "1+local" || p.PURL != "pkg:pypi/foo@1%2Blocal" {
			t.Fatal(p.Version, p.PURL)
		}
	}
}

func TestProjectionDoesNotGuessAmbiguousGroup(t *testing.T) {
	doc := frontendDocument{}
	doc.Dimensions.Occurrences = []map[string]any{
		selected(".", "poetry.lock", "package[0].groups[0]", "pypi:parent@1"),
		selected(".", "poetry.lock", "package[1].groups[0]", "pypi:child@1"),
		selected(".", "poetry.lock", "package[1].groups[1]", "pypi:child@1"),
	}
	doc.Dimensions.Relationships = []map[string]any{{"parent": "pypi:parent@1", "child": "pypi:child@1",
		"path": "poetry.lock", "root": ".", "parent_locator": "package[0].groups[0]", "child_locator": "package[1]", "kind": "dependency", "locator": "package[0].dependencies[0]"}}
	_, relationships, result, err := project(context.Background(), doc)
	if err != nil || len(relationships) != 0 || len(result.UnmappedRelationships) != 1 {
		t.Fatal(err, relationships, result)
	}
}

func TestSamePurlInformationalEdgeRetained(t *testing.T) {
	doc := frontendDocument{}
	doc.Dimensions.Occurrences = []map[string]any{
		selected(".", "pdm.lock", "package[0]", "pypi:foo@1"),
		selected(".", "pdm.lock", "package[1]", "pypi:foo@1"),
	}
	doc.Dimensions.Occurrences[0]["extras"] = []any{"test"}
	doc.Dimensions.Relationships = []map[string]any{{"parent": "pypi:foo@1", "child": "pypi:foo@1",
		"path": "pdm.lock", "root": ".", "parent_locator": "package[0]", "child_locator": "package[1]",
		"activation": "unknown", "kind": "dependency", "locator": "package[0].dependencies[0]"}}
	pkgs, relationships, result, err := project(context.Background(), doc)
	if err != nil || len(relationships) != 1 || len(result.Relationships) != 1 {
		t.Fatal(err, relationships, result)
	}
	r := relationships[0]
	if r.Type != conditionalDependency || r.From.ID() != pkgs[1].ID() || r.To.ID() != pkgs[0].ID() || r.From.ID() == r.To.ID() {
		t.Fatal("conditional direction/occurrence identity changed", r)
	}
}

func TestSelectedOnlyAndDuplicateRefusal(t *testing.T) {
	for _, identity := range []string{"pypi:foo", "pypi:foo@", "npm:foo@1"} {
		doc := frontendDocument{}
		doc.Dimensions.Occurrences = []map[string]any{selected(".", "requirements.txt", "line:1", identity)}
		if _, _, _, err := project(context.Background(), doc); err == nil {
			t.Fatal("accepted unresolved/bad identity", identity)
		}
	}
	doc := frontendDocument{}
	a := selected(".", "requirements.txt", "line:1", "pypi:foo@1")
	doc.Dimensions.Occurrences = []map[string]any{a, a}
	if _, _, _, err := project(context.Background(), doc); err == nil {
		t.Fatal("accepted duplicate occurrence")
	}
}

func TestSyftJSONRoundtripPreservesOccurrenceID(t *testing.T) {
	doc := frontendDocument{}
	a := selected(".", "uv.lock", "package[0]", "pypi:foo@1+local")
	doc.Dimensions.Occurrences = []map[string]any{a}
	pkgs, _, _, err := project(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	s := sbom.SBOM{}
	s.Artifacts.Packages = pkg.NewCollection(pkgs...)
	var output bytes.Buffer
	if err := syftjson.NewFormatEncoder().Encode(&output, s); err != nil {
		t.Fatal(err)
	}
	decoded, _, _, err := syftjson.NewFormatDecoder().Decode(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	actual := decoded.Artifacts.Packages.Sorted()
	if len(actual) != 1 || actual[0].ID() != pkgs[0].ID() || actual[0].PURL != pkgs[0].PURL {
		t.Fatal("serialized identity lost", actual)
	}
	var raw map[string]any
	if err := json.Unmarshal(output.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedCodeInsideSourceRefused(t *testing.T) {
	root := t.TempDir()
	code := filepath.Join(root, "code.py")
	if err := os.WriteFile(code, []byte("pass"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{code, "relative"} {
		if _, err := externalPath(root, path); err == nil {
			t.Fatal("accepted untrusted code path", path)
		}
	}
	other := t.TempDir()
	link := filepath.Join(other, "code.py")
	if err := os.Symlink(code, link); err != nil {
		t.Fatal(err)
	}
	if _, err := externalPath(root, link); err == nil {
		t.Fatal("accepted code symlink into source")
	}
}
