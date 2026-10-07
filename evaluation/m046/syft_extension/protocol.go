package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

var normalizedName = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// PEP440 lexical grammar, matching packaging25.0/version.py VERSION_PATTERN;
// no numeric conversion/comparison or interpretation as an installed version.
var exactVersion = regexp.MustCompile(`(?i)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?(?:[-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func sourcePath(value string, root bool) bool {
	return value != "" && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\\") && !path.IsAbs(value) &&
		value == path.Clean(value) && value != ".." && !strings.HasPrefix(value, "../") && (root || value != ".")
}

func selectedIdentity(value string) bool {
	name, version, ok := strings.Cut(strings.TrimPrefix(value, "pypi:"), "@")
	return strings.HasPrefix(value, "pypi:") && ok && len(value) <= 16384 && normalizedName.MatchString(name) && exactVersion.MatchString(version)
}

func nullableText(record map[string]any, key string) bool {
	value, present := record[key]
	if !present {
		return false
	}
	if value == nil {
		return true
	}
	text, ok := value.(string)
	return ok && len(text) <= 16384 && !strings.ContainsRune(text, 0)
}

func stringList(value any) bool {
	items, ok := value.([]any)
	if !ok || len(items) > 100000 {
		return false
	}
	for _, item := range items {
		s, ok := item.(string)
		if !ok || len(s) > 16384 || strings.ContainsRune(s, 0) {
			return false
		}
	}
	return true
}

func validateOccurrence(record map[string]any) error {
	if !selectedIdentity(textField(record, "package")) || !sourcePath(textField(record, "path"), false) || !sourcePath(textField(record, "root"), true) {
		return errors.New("invalid-selected-occurrence")
	}
	for _, field := range []string{"locator", "scope", "selection", "relationship", "activation"} {
		text, ok := record[field].(string)
		if !ok || text == "" || len(text) > 16384 || strings.ContainsRune(text, 0) {
			return errors.New("invalid-occurrence-fields")
		}
	}
	selection := textField(record, "selection")
	if selection != "declared-pin" && selection != "constrained" && selection != "locked" {
		return errors.New("invalid-selection-evidence")
	}
	activation := textField(record, "activation")
	if activation != "unknown" && activation != "unconditional" {
		return errors.New("invalid-activation")
	}
	for _, field := range []string{"marker", "requires_python", "declared_range"} {
		if !nullableText(record, field) {
			return errors.New("invalid-occurrence-context")
		}
	}
	if !stringList(record["extras"]) || !stringList(record["hashes"]) {
		return errors.New("invalid-occurrence-arrays")
	}
	return nil
}

func validateEdge(record map[string]any) error {
	if !selectedIdentity(textField(record, "parent")) || !selectedIdentity(textField(record, "child")) ||
		!sourcePath(textField(record, "path"), false) || !sourcePath(textField(record, "root"), true) ||
		textField(record, "kind") != "dependency" || textField(record, "locator") == "" {
		return errors.New("invalid-evidenced-edge")
	}
	for _, field := range []string{"parent_locator", "child_locator", "marker", "scope", "group", "activation", "constraint_dialect", "marker_semantics", "exact_version", "child_source_identity", "declared_constraint"} {
		if _, present := record[field]; present && !nullableText(record, field) {
			return errors.New("invalid-edge-context")
		}
	}
	if value, present := record["extras"]; present && !stringList(value) {
		return errors.New("invalid-edge-extras")
	}
	return nil
}

// Duplicate object keys, excessive nesting/tokens and trailing documents refuse
// the complete combined result. The enclosing 64MiB stream/cgroup bounds still
// govern decoder allocations; token checks are not a substitute for that bound.
func uniqueJSON(ctx context.Context, decoder *json.Decoder, depth int, count *int) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*count++
	if depth > 32 || *count > 10000000 {
		return nil, errors.New("frontend-json-budget-exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("invalid-json-key")
				}
				if _, duplicate := object[key]; duplicate {
					return nil, errors.New("duplicate-json-key")
				}
				value, err := uniqueJSON(ctx, decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid-json-object")
			}
			return object, nil
		case '[':
			items := []any{}
			for decoder.More() {
				value, err := uniqueJSON(ctx, decoder, depth+1, count)
				if err != nil {
					return nil, err
				}
				if len(items) >= 100000 {
					return nil, errors.New("frontend-record-budget-exceeded")
				}
				items = append(items, value)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid-json-array")
			}
			return items, nil
		default:
			return nil, errors.New("unexpected-json-delimiter")
		}
	}
	return token, nil
}

func decodeFrontend(ctx context.Context, content []byte) (frontendDocument, error) {
	document := frontendDocument{}
	if len(content) > maxOutput {
		return document, errOutputLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	count := 0
	value, err := uniqueJSON(ctx, decoder, 0, &count)
	if err != nil {
		return document, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return document, errors.New("trailing-frontend-json")
	}
	root, ok := value.(map[string]any)
	if !ok {
		return document, errors.New("invalid-frontend-envelope")
	}
	document.Schema = textField(root, "schema_version")
	document.Status = textField(root, "inventory_status")
	if document.Schema != "m046-static-inventory-prototype-v5" || (document.Status != "complete" && document.Status != "partial") ||
		textField(root, "sbom_status") != "not-run" || textField(root, "matching_status") != "not-run" || textField(root, "coverage") != "prototype-static-python" {
		return document, errors.New("unaccepted-static-frontend-result")
	}
	for _, field := range []string{"packages", "edges", "application_identities", "refusal_codes"} {
		if _, ok := root[field].([]any); !ok {
			return document, errors.New("missing-frontend-projection")
		}
	}
	dimensions, ok := root["semantic_dimensions"].(map[string]any)
	if !ok {
		return document, errors.New("missing-frontend-dimensions")
	}
	for _, field := range []string{"inputs", "occurrences", "relationships", "declaration_records", "references", "roots", "applications", "environment_records"} {
		items, ok := dimensions[field].([]any)
		if !ok {
			return document, errors.New("missing-frontend-dimension")
		}
		if field == "occurrences" || field == "relationships" {
			rows := []map[string]any{}
			for _, item := range items {
				row, ok := item.(map[string]any)
				if !ok {
					return document, errors.New("invalid-frontend-row")
				}
				rows = append(rows, row)
			}
			if field == "occurrences" {
				document.Dimensions.Occurrences = rows
			} else {
				document.Dimensions.Relationships = rows
			}
		}
	}
	fidelity, ok := dimensions["fidelity"].(map[string]any)
	if !ok {
		return document, errors.New("missing-frontend-fidelity")
	}
	for _, field := range []string{"discovery", "parsing", "enumeration", "version_selection", "graph", "environment"} {
		if _, ok := fidelity[field].(string); !ok {
			return document, errors.New("invalid-frontend-fidelity")
		}
	}
	wanted := map[string]bool{}
	for _, record := range document.Dimensions.Occurrences {
		if err := validateOccurrence(record); err != nil {
			return document, err
		}
		wanted[textField(record, "package")] = true
	}
	packages := root["packages"].([]any)
	if len(packages) != len(wanted) {
		return document, errors.New("frontend-package-projection-mismatch")
	}
	for _, raw := range packages {
		identity, ok := raw.(string)
		if !ok || !wanted[identity] {
			return document, errors.New("frontend-package-projection-mismatch")
		}
		delete(wanted, identity)
	}
	for _, edge := range document.Dimensions.Relationships {
		if err := validateEdge(edge); err != nil {
			return document, err
		}
	}
	if err := validateDimensions(root, dimensions, fidelity); err != nil {
		return document, err
	}
	return document, nil
}
