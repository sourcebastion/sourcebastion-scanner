package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

const catalogerName = "m046-static-python-cataloger"
const conditionalDependency artifact.RelationshipType = "m046-informational-dependency"

// Trusted controller-prepared paths, never customer configuration. Runtime and
// complete source/wheel identity are verified by the evaluation runner. The
// immutable source mount and shared cgroup remain the scan boundary.
type frontendCataloger struct {
	root, python, cli string
	inventory         json.RawMessage
	projection        projection
	expectedPackages  map[string]string
	expectedRelations map[string]int
}

type projection struct {
	Occurrences           []occurrenceBinding   `json:"occurrences"`
	Relationships         []relationshipBinding `json:"relationships"`
	UnmappedRelationships []int                 `json:"unmapped_relationships"`
	UnmappedReasons       map[int]string        `json:"unmapped_reasons"`
}
type occurrenceBinding struct {
	Index int    `json:"index"`
	ID    string `json:"syft_id"`
}
type relationshipBinding struct {
	Index  int    `json:"index"`
	Parent string `json:"parent_syft_id"`
	Child  string `json:"child_syft_id"`
}
type frontendDocument struct {
	Schema     string `json:"schema_version"`
	Status     string `json:"inventory_status"`
	Dimensions struct {
		Occurrences   []map[string]any `json:"occurrences"`
		Relationships []map[string]any `json:"relationships"`
	} `json:"semantic_dimensions"`
}

func (f *frontendCataloger) Name() string { return catalogerName }

func externalPath(root, candidate string) (string, error) {
	if !filepath.IsAbs(candidate) {
		return "", errors.New("absolute-trusted-code-path-required")
	}
	lexical, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil || lexical == "." || (lexical != ".." && !strings.HasPrefix(lexical, ".."+string(filepath.Separator))) {
		return "", errors.New("trusted-code-inside-source-refused")
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", errors.New("unavailable-trusted-code")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("unavailable-source-root")
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return "", errors.New("trusted-code-inside-source-refused")
	}
	// Preserve a trusted venv executable path: resolving it before exec would
	// silently choose the base interpreter's different site-packages.
	return filepath.Clean(candidate), nil
}

func (f *frontendCataloger) Catalog(ctx context.Context, _ file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	python, err := externalPath(f.root, f.python)
	if err != nil {
		return nil, nil, err
	}
	cli, err := externalPath(f.root, f.cli)
	if err != nil {
		return nil, nil, err
	}
	// One trusted interpreter is intentional; project execution remains forbidden.
	cmd := exec.CommandContext(ctx, python, "-I", "-B", cli, "--root", f.root)
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/nonexistent", "HOME=/nonexistent", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	cmd.WaitDelay = time.Second
	stdout := &boundedBuffer{limit: maxOutput, ctx: ctx}
	stderr := &boundedBuffer{limit: 64 * 1024, ctx: ctx}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, nil, errors.New("static-frontend-failed")
	}
	document, err := decodeFrontend(ctx, stdout.Bytes())
	if err != nil {
		return nil, nil, err
	}
	packages, relations, projection, err := project(ctx, document)
	if err != nil {
		return nil, nil, err
	}
	f.inventory = append(json.RawMessage(nil), stdout.Bytes()...)
	f.projection = projection
	f.expectedPackages = map[string]string{}
	for _, p := range packages {
		f.expectedPackages[string(p.ID())] = packageSignature(p)
	}
	f.expectedRelations = map[string]int{}
	for _, r := range relations {
		f.expectedRelations[relationshipSignature(r)]++
	}
	return packages, relations, nil
}

func textField(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

func occurrenceKey(record map[string]any) string {
	// Full typed occurrence enters ID: roots/scopes/marker/extras/local versions
	// stay distinct even when purls and file paths are equal. JSON map keys sort.
	content, _ := json.Marshal(record)
	sum := sha256.Sum256(append([]byte("m046-syft-occurrence-v1\x00m046-static-inventory-prototype-v5\x00"), content...))
	return "m046-" + hex.EncodeToString(sum[:])
}

func project(ctx context.Context, document frontendDocument) ([]pkg.Package, []artifact.Relationship, projection, error) {
	var packages []pkg.Package
	var relations []artifact.Relationship
	result := projection{Occurrences: []occurrenceBinding{}, Relationships: []relationshipBinding{}, UnmappedRelationships: []int{}, UnmappedReasons: map[int]string{}}
	seen := map[string]bool{}
	type key struct{ root, path, identity string }
	index := map[key][]int{}
	for i, record := range document.Dimensions.Occurrences {
		if err := ctx.Err(); err != nil {
			return nil, nil, result, err
		}
		if err := validateOccurrence(record); err != nil {
			return nil, nil, result, err
		}
		identity := textField(record, "package")
		name, version, ok := strings.Cut(strings.TrimPrefix(identity, "pypi:"), "@")
		path, locator := textField(record, "path"), textField(record, "locator")
		if !strings.HasPrefix(identity, "pypi:") || !ok || name == "" || version == "" || path == "" || locator == "" {
			return nil, nil, result, errors.New("invalid-selected-occurrence")
		}
		id := occurrenceKey(record)
		if seen[id] {
			return nil, nil, result, errors.New("duplicate-occurrence-identity")
		}
		seen[id] = true
		location := file.NewLocation(path).WithAnnotation("m046:occurrence", id).WithAnnotation("m046:locator", locator)
		p := pkg.Package{Name: name, Version: version, Type: pkg.PythonPkg, Language: pkg.Python, FoundBy: catalogerName,
			PURL: packageurl.NewPackageURL("pypi", "", name, version, nil, "").ToString(), Locations: file.NewLocationSet(location)}
		// No invented installed-package metadata or custom unregistered Metadata
		// type. Stock decoders must retain ID/location; rich data lives in sidecar.
		p.OverrideID(artifact.ID(id))
		packages = append(packages, p)
		result.Occurrences = append(result.Occurrences, occurrenceBinding{Index: i, ID: id})
		k := key{textField(record, "root"), path, identity}
		index[k] = append(index[k], i)
	}
	steps := 0
	for i, edge := range document.Dimensions.Relationships {
		if err := ctx.Err(); err != nil {
			return nil, nil, result, err
		}
		if err := validateEdge(edge); err != nil {
			return nil, nil, result, err
		}
		parents, children := []int{}, []int{}
		parentKey := key{textField(edge, "root"), textField(edge, "path"), textField(edge, "parent")}
		childKey := key{textField(edge, "root"), textField(edge, "path"), textField(edge, "child")}
		for _, n := range index[parentKey] {
			if err := ctx.Err(); err != nil {
				return nil, nil, result, err
			}
			steps++
			if steps > 5000000 {
				return nil, nil, result, errors.New("projection-step-budget-exceeded")
			}
			record := document.Dimensions.Occurrences[n]
			if textField(record, "package") == textField(edge, "parent") && (edge["parent_locator"] == nil || textField(record, "locator") == textField(edge, "parent_locator")) {
				parents = append(parents, n)
			}
		}
		for _, n := range index[childKey] {
			if err := ctx.Err(); err != nil {
				return nil, nil, result, err
			}
			steps++
			if steps > 5000000 {
				return nil, nil, result, errors.New("projection-step-budget-exceeded")
			}
			record := document.Dimensions.Occurrences[n]
			if textField(record, "package") == textField(edge, "child") && (edge["child_locator"] == nil || textField(record, "locator") == textField(edge, "child_locator") || strings.HasPrefix(textField(record, "locator"), textField(edge, "child_locator")+".groups[")) {
				children = append(children, n)
			}
		}
		// Group/marker variants cannot authorize a guessed child occurrence.
		// Keep unprojectable edges in the complete rich sidecar and flag mapping.
		if len(parents) != 1 || len(children) != 1 {
			result.UnmappedRelationships = append(result.UnmappedRelationships, i)
			reason := "ambiguous-child-occurrence"
			if len(parents) == 0 {
				reason = "missing-parent-occurrence"
			} else if len(parents) > 1 {
				reason = "ambiguous-parent-occurrence"
			} else if len(children) == 0 {
				reason = "missing-child-occurrence"
			}
			result.UnmappedReasons[i] = reason
			continue
		}
		parent, child := packages[parents[0]], packages[children[0]]
		relations = append(relations, artifact.Relationship{From: child, To: parent, Type: conditionalDependency, Data: edge})
		result.Relationships = append(result.Relationships, relationshipBinding{Index: i, Parent: string(parent.ID()), Child: string(child.ID())})
	}
	return packages, relations, result, nil
}

func packageSignature(p pkg.Package) string {
	content, _ := json.Marshal([]any{p.Name, p.Version, p.Type, p.PURL, p.Language, p.Locations.ToSlice()})
	return string(content)
}

func relationshipSignature(r artifact.Relationship) string {
	content, _ := json.Marshal([]any{r.From.ID(), r.To.ID(), r.Type, r.Data})
	return string(content)
}

func (f *frontendCataloger) validateBindings(document *sbom.SBOM) error {
	actual := map[string]pkg.Package{}
	for _, p := range document.Artifacts.Packages.Sorted() {
		if p.FoundBy == catalogerName {
			actual[string(p.ID())] = p
		}
	}
	if len(actual) != len(f.expectedPackages) {
		return errors.New("changed-occurrence-count")
	}
	for id, expected := range f.expectedPackages {
		p, ok := actual[id]
		if !ok || packageSignature(p) != expected {
			return errors.New("changed-occurrence-binding")
		}
	}
	actualRelations := map[string]int{}
	for _, r := range document.Relationships {
		if r.Type == conditionalDependency {
			actualRelations[relationshipSignature(r)]++
		}
	}
	a, _ := json.Marshal(f.expectedRelations)
	b, _ := json.Marshal(actualRelations)
	if string(a) != string(b) {
		return errors.New("changed-informational-relationships")
	}
	return nil
}
