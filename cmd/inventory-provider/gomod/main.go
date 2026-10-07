// Fixed, offline source parser. Output is private source evidence, never a
// selected module inventory. No customer Go command or project code executes.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

const maxInput = 2 * 1024 * 1024
const maxOutput = 64 * 1024 * 1024
const maxRecords = 100000

type requirement struct {
	Ordinal        int    `json:"ordinal"`
	Name           string `json:"name"`
	MinimumVersion string `json:"minimum_version"`
	Indirect       bool   `json:"indirect"`
	Line           int    `json:"line"`
	StartByte      int    `json:"start_byte"`
	EndByte        int    `json:"end_byte"`
}
type observation struct {
	SchemaVersion        string        `json:"schema_version"`
	Parser               string        `json:"parser"`
	SourceSHA256         string        `json:"source_sha256"`
	Module               string        `json:"module"`
	Requirements         []requirement `json:"requirements"`
	UnassessedDirectives []string      `json:"unassessed_directives"`
	SelectedVersions     string        `json:"selected_versions"`
	Graph                string        `json:"graph"`
}

func observe(content []byte) (*observation, error) {
	if len(content) > maxInput || !utf8.Valid(content) || bytes.Count(content, []byte("\n")) > maxRecords {
		return nil, errors.New("go-source-input-refused")
	}
	// Parse, rather than ParseLax: unknown future directives cannot disappear.
	f, err := modfile.Parse("source.go.mod", content, nil)
	if err != nil {
		return nil, errors.New("invalid-go-source-syntax")
	}
	if f.Module == nil || module.CheckImportPath(f.Module.Mod.Path) != nil || len(f.Module.Mod.Path) > 512 {
		return nil, errors.New("unsupported-go-module-identity")
	}
	sum := sha256.Sum256(content)
	result := &observation{SchemaVersion: "sourcebastion.go-source-observation/1", Parser: "golang.org/x/mod/modfile@v0.41.0", SourceSHA256: hex.EncodeToString(sum[:]), Module: f.Module.Mod.Path, Requirements: []requirement{}, UnassessedDirectives: []string{}, SelectedVersions: "unreported", Graph: "unreported"}
	reasons := map[string]bool{}
	count := 0
	for _, expr := range f.Syntax.Stmt {
		switch node := expr.(type) {
		case *modfile.Line:
			count++
			if len(node.Token) > 0 && node.Token[0] != "module" && node.Token[0] != "require" && node.Token[0] != "go" {
				reasons["unassessed-"+node.Token[0]+"-directive"] = true
			}
		case *modfile.LineBlock:
			count += len(node.Line)
			if len(node.Token) > 0 && node.Token[0] != "require" {
				reasons["unassessed-"+node.Token[0]+"-directive"] = true
			}
		default:
			// Comments have no package semantics.
		}
		if count > maxRecords {
			return nil, errors.New("go-source-record-budget-exceeded")
		}
	}
	seen := map[string]bool{}
	for ordinal, r := range f.Require {
		if len(r.Mod.Path) > 512 || len(r.Mod.Version) > 256 || module.Check(r.Mod.Path, r.Mod.Version) != nil {
			return nil, errors.New("unsupported-go-requirement-identity")
		}
		if seen[r.Mod.Path] {
			reasons["duplicate-go-requirement"] = true
		}
		seen[r.Mod.Path] = true
		start, end := r.Syntax.Span()
		result.Requirements = append(result.Requirements, requirement{ordinal, r.Mod.Path, r.Mod.Version, r.Indirect, start.Line, start.Byte, end.Byte})
	}
	for reason := range reasons {
		result.UnassessedDirectives = append(result.UnassessedDirectives, reason)
	}
	sort.Strings(result.UnassessedDirectives)
	return result, nil
}

func run(ctx context.Context, input io.Reader, output io.Writer, limit int) error {
	if limit < 1 || limit > maxOutput {
		return errors.New("invalid-go-source-output-limit")
	}
	if ctx.Err() != nil {
		return errors.New("go-source-deadline-exceeded")
	}
	// The executable's outer deadline covers a blocked stdin as well as parsing.
	type answer struct {
		document *observation
		err      error
	}
	ready := make(chan answer, 1)
	go func() {
		content, err := io.ReadAll(io.LimitReader(input, maxInput+1))
		if err != nil {
			ready <- answer{err: errors.New("go-source-input-refused")}
			return
		}
		document, err := observe(content)
		ready <- answer{document, err}
	}()
	var result answer
	select {
	case <-ctx.Done():
		return errors.New("go-source-deadline-exceeded")
	case result = <-ready:
	}
	if result.err != nil {
		return result.err
	}
	raw, err := json.Marshal(result.document)
	if err != nil || len(raw)+1 > limit {
		return errors.New("go-source-output-budget-exceeded")
	}
	if ctx.Err() != nil {
		return errors.New("go-source-deadline-exceeded")
	}
	written := make(chan error, 1)
	go func() {
		_, err := output.Write(append(raw, '\n'))
		written <- err
	}()
	select {
	case <-ctx.Done():
		return errors.New("go-source-deadline-exceeded")
	case err := <-written:
		if ctx.Err() != nil {
			return errors.New("go-source-deadline-exceeded")
		}
		return err
	}
}

func main() {
	runtime.GOMAXPROCS(2)
	args := flag.NewFlagSet("sourcebastion-go-source", flag.ContinueOnError)
	args.SetOutput(io.Discard)
	remaining := args.Duration("remaining", 0, "remaining outer deadline, at most 150s")
	output := args.Int("output-bytes", maxOutput, "remaining bounded output")
	if args.Parse(os.Args[1:]) != nil || args.NArg() != 0 || *remaining <= 0 || *remaining > 150*time.Second || *output < 1 || *output > maxOutput {
		fmt.Fprintln(os.Stderr, "invalid-go-source-arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *remaining)
	defer cancel()
	if err := run(ctx, os.Stdin, os.Stdout, *output); err != nil {
		// Never print library errors, source paths, tokens, or credentials.
		reason := err.Error()
		if !strings.HasPrefix(reason, "go-source-") && !strings.HasPrefix(reason, "invalid-go-source-") && !strings.HasPrefix(reason, "unsupported-go-") {
			reason = "go-source-failed"
		}
		fmt.Fprintln(os.Stderr, reason)
		os.Exit(2)
	}
}
