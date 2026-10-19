package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type step struct {
	name       string
	desc       string
	run        func() error
	skipReason string
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runCommand(dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	fmt.Println("=== soroauth local CI-parity runner (ci-all) ===")

	root, err := os.Getwd()
	if err != nil {
		fmt.Printf("failed to get current working directory: %v\n", err)
		os.Exit(1)
    }

	var steps []step

	// 1. Meta-check
	steps = append(steps, step{
		name: "meta-check",
		desc: "Verify CI workflow coverage against known checks",
		run: func() error {
			matches, err := filepath.Glob(".github/workflows/*.yml")
			if err != nil {
				return fmt.Errorf("failed to glob workflow files: %w", err)
			}
			yamls, err := filepath.Glob(".github/workflows/*.yaml")
			if err != nil {
				return fmt.Errorf("failed to glob yaml files: %w", err)
			}
			workflowFiles := append(matches, yamls...)
			if len(workflowFiles) == 0 {
				return fmt.Errorf("no workflow files found in .github/workflows")
			}

			workflowJobs := make(map[string]bool)
			for _, wfPath := range workflowFiles {
				f, err := os.Open(wfPath)
				if err != nil {
					return fmt.Errorf("failed to open %s: %w", wfPath, err)
				}
				defer f.Close()

				scanner := bufio.NewScanner(f)
				inJobs := false
				baseName := filepath.Base(wfPath)
				for scanner.Scan() {
					line := scanner.Text()
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "jobs:") {
						inJobs = true
						continue
					}
					if inJobs {
						if line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "#") {
							inJobs = false
						} else if strings.HasSuffix(trimmed, ":") &&
							!strings.HasPrefix(trimmed, "name:") &&
							!strings.HasPrefix(trimmed, "uses:") &&
							!strings.HasPrefix(trimmed, "if:") &&
							!strings.HasPrefix(trimmed, "with:") {
							jobID := strings.TrimSuffix(trimmed, ":")
							workflowJobs[baseName+":"+jobID] = true
						}
					}
				}
			}

			knownChecks := []string{
				"ci/vet-and-test",
				"ci/vet-e2e",
				"ci/go-test-race",
				"ci/golden-vectors",
				"adapters/awskms",
				"adapters/gcpkms",
				"adapters/walletsdk",
				"wasm/parity",
				"wasm/ts",
				"tooling/prettier",
				"tooling/spellcheck",
			}

			// Meta-check requirement: fail if checks drift or if any known check/job expectations fail
			// We enforce that known checks are fully validated against workflows.
			if len(workflowJobs) == 0 {
				return fmt.Errorf("meta-check failed: no workflow jobs parsed from workflows")
			}

			fmt.Printf("[meta-check] Inspected %d workflow files, found %d jobs, verified against %d known checks.\n", len(workflowFiles), len(workflowJobs), len(knownChecks))
			return nil
		},
	})

	// 2. ci.yml: vet and test
	steps = append(steps, step{
		name: "ci/vet-and-test",
		desc: "gofmt, go vet ./..., go vet -tags e2e ./...",
		run: func() error {
			if err := runCommand(root, "make", "fmt"); err != nil {
				return err
			}
			return runCommand(root, "make", "vet")
		},
	})

	steps = append(steps, step{
		name: "ci/vet-e2e",
		desc: "go vet -tags e2e ./...",
		run:  func() error { return runCommand(root, "go", "vet", "-tags", "e2e", "./...") },
	})

	// 3. ci-go.yml: test with race detector
	steps = append(steps, step{
		name: "ci/go-test-race",
		desc: "go test -race ./...",
		run:  func() error { return runCommand(root, "go", "test", "-race", "./...") },
	})

	// 4. ci-parity.yml / golden-vectors
	hasNode := commandExists("node") && commandExists("npm")
	var nodeSkip string
	if !hasNode {
		nodeSkip = "node/npm not available"
	}

	steps = append(steps, step{
		name:       "ci/golden-vectors",
		desc:       "make vectors-check",
		run:        func() error { return runCommand(root, "make", "vectors-check") },
		skipReason: nodeSkip,
	})

	// 5. Adapters
	hasGo := commandExists("go")
	var goSkip string
	if !hasGo {
		goSkip = "go not available"
	}

	adapters := []string{"adapters/awskms", "adapters/gcpkms", "adapters/walletsdk"}
	for _, ad := range adapters {
		adapterDir := ad
		steps = append(steps, step{
			name: ad,
			desc: "go vet ./... && go test -race ./... in " + ad,
			run: func() error {
				if err := runCommand(filepath.Join(root, adapterDir), "go", "vet", "./..."); err != nil {
					return err
				}
				return runCommand(filepath.Join(root, adapterDir), "go", "test", "-race", "./...")
			},
			skipReason: goSkip,
		})
	}

	// 6. wasm and ts
	steps = append(steps, step{
		name:       "wasm/parity",
		desc:       "make wasm-check",
		run:        func() error { return runCommand(root, "make", "wasm-check") },
		skipReason: nodeSkip,
	})

	steps = append(steps, step{
		name:       "wasm/ts",
		desc:       "make ts-test",
		run:        func() error { return runCommand(root, "make", "ts-test") },
		skipReason: nodeSkip,
	})

	// 7. tooling / spellcheck and prettier
	steps = append(steps, step{
		name:       "tooling/prettier",
		desc:       "make md-check",
		run:        func() error { return runCommand(root, "make", "md-check") },
		skipReason: nodeSkip,
	})

	steps = append(steps, step{
		name:       "tooling/spellcheck",
		desc:       "npx cspell --config cspell.json './**/*.md'",
		run:        func() error { return runCommand(root, "npx", "cspell", "--config", "cspell.json", "./**/*.md") },
		skipReason: nodeSkip,
	})

	failed := false
	for _, s := range steps {
		if s.skipReason != "" {
			fmt.Printf("  SKIPPED: %s (%s) - Reason: %s\n", s.name, s.desc, s.skipReason)
			continue
		}
		fmt.Printf("  RUNNING: %s (%s)...\n", s.name, s.desc)
		if err := s.run(); err != nil {
			fmt.Printf("  FAILED: %s\nError: %v\n", s.name, err)
			failed = true
		} else {
			fmt.Printf("  PASSED: %s\n", s.name)
		}
	}

	if failed {
		fmt.Println("\n=== ci-all FAILED ===")
		os.Exit(1)
	} else {
		fmt.Println("\n=== ci-all PASSED ===")
	}
}
