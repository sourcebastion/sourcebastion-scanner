package main

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

func member(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func requiredText(row map[string]any, fields ...string) bool {
	for _, field := range fields {
		value, ok := row[field].(string)
		if !ok || value == "" || len(value) > 16384 || strings.ContainsRune(value, 0) {
			return false
		}
	}
	return true
}

func summarySet(raw any, expected map[string]bool) bool {
	items, ok := raw.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	for _, item := range items {
		content, err := json.Marshal(item)
		if err != nil || !expected[string(content)] {
			return false
		}
		delete(expected, string(content))
	}
	return len(expected) == 0
}

func canonicalValue(value any) string { content, _ := json.Marshal(value); return string(content) }

func validateDimensions(root, dimensions, fidelity map[string]any) error {
	bad := func() error { return errors.New("invalid-rich-frontend-contract") }
	for _, field := range []string{"discovery", "parsing", "enumeration", "version_selection"} {
		if !member(textField(fidelity, field), "complete", "partial") {
			return bad()
		}
	}
	if !member(textField(fidelity, "graph"), "unknown", "evidenced-only") || !member(textField(fidelity, "environment"), "unknown", "conditional-unknown", "unconditional") {
		return bad()
	}
	roots := map[string]bool{}
	for _, raw := range dimensions["roots"].([]any) {
		value, ok := raw.(string)
		if !ok || !sourcePath(value, true) || roots[value] {
			return bad()
		}
		roots[value] = true
	}
	inputs := map[string]map[string]any{}
	inputRoots := map[string]map[string]bool{}
	rootUnion := map[string]bool{}
	partial := textField(fidelity, "discovery") == "partial"
	environmentUnknown := false
	for _, raw := range dimensions["inputs"].([]any) {
		row, ok := raw.(map[string]any)
		if !ok || !requiredText(row, "path", "format", "disposition", "reason") || !sourcePath(textField(row, "path"), false) {
			return bad()
		}
		path := textField(row, "path")
		if _, duplicate := inputs[path]; duplicate {
			return bad()
		}
		inputs[path] = row
		disposition := textField(row, "disposition")
		if !member(disposition, "parsed", "declaration-only", "ignored", "unsupported", "malformed", "unsafe", "budget-exceeded") {
			return bad()
		}
		if member(disposition, "unsupported", "malformed", "unsafe", "budget-exceeded") {
			partial = true
		}
		if disposition == "unsupported" && textField(row, "reason") != "missing-lock-source" {
			environmentUnknown = true
		}
		if !stringList(row["roots"]) || len(row["roots"].([]any)) == 0 {
			return bad()
		}
		for _, r := range row["roots"].([]any) {
			if !roots[r.(string)] {
				return bad()
			}
			if inputRoots[path] == nil {
				inputRoots[path] = map[string]bool{}
			}
			inputRoots[path][r.(string)] = true
			rootUnion[r.(string)] = true
		}
		sha, present := row["sha256"]
		if !present {
			return bad()
		}
		if sha == nil && member(disposition, "parsed", "declaration-only") {
			return bad()
		}
		if sha != nil {
			s, ok := sha.(string)
			if !ok || !sha256Hex.MatchString(s) {
				return bad()
			}
		}
	}
	if len(rootUnion) != len(roots) {
		return bad()
	}
	checkLocated := func(row map[string]any, locator bool) bool {
		return requiredText(row, "path", "root") && inputs[textField(row, "path")] != nil && inputRoots[textField(row, "path")][textField(row, "root")] &&
			(!locator || requiredText(row, "locator"))
	}
	conditional := false
	occurrences := map[string]map[string]bool{}
	type located struct{ root, path, identity string }
	locatedOccurrences := map[located][]map[string]any{}
	for _, raw := range dimensions["occurrences"].([]any) {
		row := raw.(map[string]any)
		if !checkLocated(row, true) {
			return bad()
		}
		if textField(row, "activation") == "unknown" {
			conditional = true
		}
		key := textField(row, "root")
		if occurrences[key] == nil {
			occurrences[key] = map[string]bool{}
		}
		occurrences[key][textField(row, "package")] = true
		where := located{key, textField(row, "path"), textField(row, "package")}
		locatedOccurrences[where] = append(locatedOccurrences[where], row)
	}
	edges := map[string]bool{}
	steps := 0
	for _, raw := range dimensions["relationships"].([]any) {
		row := raw.(map[string]any)
		if !checkLocated(row, true) {
			return bad()
		}
		key := textField(row, "root")
		if !occurrences[key][textField(row, "parent")] || !occurrences[key][textField(row, "child")] {
			return bad()
		}
		for _, endpoint := range []string{"parent", "child"} {
			found := false
			for _, candidate := range locatedOccurrences[located{key, textField(row, "path"), textField(row, endpoint)}] {
				steps++
				if steps > 5000000 {
					return bad()
				}
				locator := textField(row, endpoint+"_locator")
				actual := textField(candidate, "locator")
				if locator == "" || locator == actual || (endpoint == "child" && strings.HasPrefix(actual, locator+".groups[")) {
					found = true
					break
				}
			}
			if !found {
				return bad()
			}
		}
		edges[canonicalValue([]string{textField(row, "parent"), textField(row, "child")})] = true
	}
	if !summarySet(root["edges"], edges) {
		return bad()
	}
	for _, raw := range dimensions["declaration_records"].([]any) {
		row, ok := raw.(map[string]any)
		if !ok || !checkLocated(row, true) || !requiredText(row, "name", "scope", "classification") ||
			!strings.HasPrefix(textField(row, "name"), "pypi:") || !normalizedName.MatchString(strings.TrimPrefix(textField(row, "name"), "pypi:")) ||
			!nullableText(row, "range") || row["range"] == nil || !nullableText(row, "marker") || !stringList(row["extras"]) ||
			!member(textField(row, "classification"), "unknown", "direct-declared") {
			return bad()
		}
		if row["marker"] != nil || strings.HasPrefix(textField(row, "scope"), "optional:") {
			conditional = true
		}
	}
	for _, raw := range dimensions["references"].([]any) {
		row, ok := raw.(map[string]any)
		if !ok || !checkLocated(row, true) || !member(textField(row, "kind"), "include", "constraint", "version-evidence", "include-refused", "constraint-refused") || !nullableText(row, "target") {
			return bad()
		}
		// Refused targets are bounded evidence strings, never paths to read or
		// project. Preserve an outside-source target in an honestly partial
		// inventory instead of rejecting the entire diagnostic bundle.
		refused := strings.HasSuffix(textField(row, "kind"), "-refused")
		if refused && !member(textField(inputs[textField(row, "path")], "disposition"), "unsupported", "malformed", "unsafe", "budget-exceeded") {
			return bad()
		}
		if !refused && row["target"] != nil && !sourcePath(textField(row, "target"), false) {
			return bad()
		}
	}
	applications := map[string]bool{}
	for _, raw := range dimensions["applications"].([]any) {
		row, ok := raw.(map[string]any)
		if !ok || !checkLocated(row, false) || !selectedIdentity(textField(row, "identity")) {
			return bad()
		}
		applications[canonicalValue(textField(row, "identity"))] = true
	}
	if !summarySet(root["application_identities"], applications) {
		return bad()
	}
	for _, raw := range dimensions["environment_records"].([]any) {
		row, ok := raw.(map[string]any)
		if !ok || !checkLocated(row, true) || !requiredText(row, "requires_python") ||
			!member(textField(row, "kind"), "root", "package") || textField(row, "activation") != "unknown" {
			return bad()
		}
		if textField(row, "kind") == "package" && !occurrences[textField(row, "root")][textField(row, "package")] {
			return bad()
		}
		conditional = true
	}
	if !stringList(root["refusal_codes"]) {
		return bad()
	}
	expectedParsing := "complete"
	if partial {
		expectedParsing = "partial"
	}
	if textField(fidelity, "parsing") != expectedParsing || textField(fidelity, "enumeration") != expectedParsing {
		return bad()
	}
	if partial && textField(fidelity, "version_selection") != "partial" {
		return bad()
	}
	expectedStatus := "partial"
	if textField(fidelity, "version_selection") == "complete" {
		expectedStatus = "complete"
	}
	if textField(root, "inventory_status") != expectedStatus {
		return bad()
	}
	expectedGraph := "unknown"
	if len(dimensions["relationships"].([]any)) > 0 {
		expectedGraph = "evidenced-only"
	}
	if textField(fidelity, "graph") != expectedGraph {
		return bad()
	}
	expectedEnv := "unconditional"
	if conditional {
		expectedEnv = "conditional-unknown"
	}
	if environmentUnknown {
		expectedEnv = "unknown"
	}
	if textField(fidelity, "environment") != expectedEnv {
		return bad()
	}
	return nil
}
