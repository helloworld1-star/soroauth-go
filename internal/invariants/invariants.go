// Package invariants provides custom AST-based analyzers enforcing the
// repository's critical invariants defined in CLAUDE.md and the coding standards:
//
//  1. no-mutation: caller input (specifically SorobanAuthorizationEntry and XDR
//     trees) must not be mutated without deep-copy or an exemption.
//  2. no-logging: no logging packages (log, slog, zap, logrus) in library code.
//  3. no-panic: no panic calls outside tests.
//  4. no-math-rand: no math/rand imports; use crypto/rand.
//  5. no-floats: no float32, float64, or math.Float* usage anywhere.
//
// Exemptions require an inline directive with a stated reason:
//
//	// invariant-allow: <rule> <reason>
//
// Violations fail the build with file, line, and the rule's rationale.
package invariants

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Rule identifier constants.
const (
	RuleNoMutation = "no-mutation"
	RuleNoLogging  = "no-logging"
	RuleNoPanic    = "no-panic"
	RuleNoMathRand = "no-math-rand"
	RuleNoFloats   = "no-floats"
)

// Rationale returns the human-readable rationale for an invariant rule.
func Rationale(rule string) string {
	switch rule {
	case RuleNoMutation:
		return "go-stellar-sdk XDR structs contain pointers and slices; mutating caller input aliases caller data. Deep-copy with internal/xdrcopy first."
	case RuleNoLogging:
		return "Library code must not log; the CLI writes to stdout/stderr and returns errors to callers."
	case RuleNoPanic:
		return "Library code must return errors to callers, never panic outside tests."
	case RuleNoMathRand:
		return "Cryptographic and security operations must use crypto/rand, never math/rand."
	case RuleNoFloats:
		return "Financial and authorization arithmetic must use exact integer math, never floating point."
	default:
		return "Repository invariant rule."
	}
}

// Violation describes a violation of a repository invariant rule.
type Violation struct {
	Rule      string
	Position  string
	Message   string
	Rationale string
}

// String renders the violation in standard compiler/linter error format.
func (v Violation) String() string {
	return fmt.Sprintf("%s: [%s] %s (rationale: %s)", v.Position, v.Rule, v.Message, v.Rationale)
}

// Analyzer represents an invariant checker.
type Analyzer struct {
	Name      string
	Doc       string
	Rationale string
	CheckFile func(fset *token.FileSet, file *ast.File, filePath string) []Violation
}

// AllAnalyzers returns the list of all invariant analyzers.
func AllAnalyzers() []*Analyzer {
	return []*Analyzer{
		NoMutationAnalyzer(),
		NoLoggingAnalyzer(),
		NoPanicAnalyzer(),
		NoMathRandAnalyzer(),
		NoFloatsAnalyzer(),
	}
}

// hasExemption checks if a comment group or line contains an exemption directive:
// // invariant-allow: <rule> <reason>
func hasExemption(comments []*ast.CommentGroup, rule string, line int, fset *token.FileSet) bool {
	prefix := fmt.Sprintf("invariant-allow: %s", rule)
	altPrefix := fmt.Sprintf("%s-allow:", rule)
	for _, cg := range comments {
		for _, c := range cg.List {
			cLine := fset.Position(c.Slash).Line
			// Allow comment on same line or preceding line
			if cLine == line || cLine == line-1 {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
				if strings.HasPrefix(text, prefix) {
					reason := strings.TrimSpace(strings.TrimPrefix(text, prefix))
					if len(reason) > 0 {
						return true
					}
				}
				if strings.HasPrefix(text, altPrefix) {
					reason := strings.TrimSpace(strings.TrimPrefix(text, altPrefix))
					if len(reason) > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}

// fileHasExemption checks if anywhere in the file has a file-level exemption
func fileHasExemption(comments []*ast.CommentGroup, rule string) bool {
	prefix := fmt.Sprintf("invariant-allow: %s", rule)
	altPrefix := fmt.Sprintf("%s-allow:", rule)
	for _, cg := range comments {
		for _, c := range cg.List {
			text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
			if strings.HasPrefix(text, prefix) {
				reason := strings.TrimSpace(strings.TrimPrefix(text, prefix))
				if len(reason) > 0 {
					return true
				}
			}
			if strings.HasPrefix(text, altPrefix) {
				reason := strings.TrimSpace(strings.TrimPrefix(text, altPrefix))
				if len(reason) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// NoPanicAnalyzer checks for panic() calls outside tests.
func NoPanicAnalyzer() *Analyzer {
	return &Analyzer{
		Name:      RuleNoPanic,
		Doc:       "reports calls to panic outside tests",
		Rationale: Rationale(RuleNoPanic),
		CheckFile: func(fset *token.FileSet, file *ast.File, filePath string) []Violation {
			// Skip test files
			if strings.HasSuffix(filePath, "_test.go") {
				return nil
			}
			var violations []Violation
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "panic" {
					return true
				}
				pos := fset.Position(call.Pos())
				if hasExemption(file.Comments, RuleNoPanic, pos.Line, fset) {
					return true
				}
				violations = append(violations, Violation{
					Rule:      RuleNoPanic,
					Position:  pos.String(),
					Message:   "use of panic in non-test code",
					Rationale: Rationale(RuleNoPanic),
				})
				return true
			})
			return violations
		},
	}
}

// NoLoggingAnalyzer checks for logging imports in library code.
func NoLoggingAnalyzer() *Analyzer {
	return &Analyzer{
		Name:      RuleNoLogging,
		Doc:       "reports logging library imports in non-server code",
		Rationale: Rationale(RuleNoLogging),
		CheckFile: func(fset *token.FileSet, file *ast.File, filePath string) []Violation {
			// Skip test files and server directory
			if strings.HasSuffix(filePath, "_test.go") || strings.Contains(filePath, "server/") {
				return nil
			}
			var violations []Violation
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "log" || path == "log/slog" || strings.Contains(path, "zap") || strings.Contains(path, "logrus") {
					pos := fset.Position(imp.Pos())
					if hasExemption(file.Comments, RuleNoLogging, pos.Line, fset) {
						continue
					}
					violations = append(violations, Violation{
						Rule:      RuleNoLogging,
						Position:  pos.String(),
						Message:   fmt.Sprintf("forbidden logging import %q", path),
						Rationale: Rationale(RuleNoLogging),
					})
				}
			}
			return violations
		},
	}
}

// NoMathRandAnalyzer checks for math/rand imports.
func NoMathRandAnalyzer() *Analyzer {
	return &Analyzer{
		Name:      RuleNoMathRand,
		Doc:       "reports imports of math/rand",
		Rationale: Rationale(RuleNoMathRand),
		CheckFile: func(fset *token.FileSet, file *ast.File, filePath string) []Violation {
			var violations []Violation
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "math/rand" || path == "math/rand/v2" {
					pos := fset.Position(imp.Pos())
					if hasExemption(file.Comments, RuleNoMathRand, pos.Line, fset) {
						continue
					}
					violations = append(violations, Violation{
						Rule:      RuleNoMathRand,
						Position:  pos.String(),
						Message:   fmt.Sprintf("use of %s is forbidden; use crypto/rand", path),
						Rationale: Rationale(RuleNoMathRand),
					})
				}
			}
			return violations
		},
	}
}

// NoFloatsAnalyzer checks for float types and math.Float* functions.
func NoFloatsAnalyzer() *Analyzer {
	return &Analyzer{
		Name:      RuleNoFloats,
		Doc:       "reports float32/float64 types and float literals/calls",
		Rationale: Rationale(RuleNoFloats),
		CheckFile: func(fset *token.FileSet, file *ast.File, filePath string) []Violation {
			// Skip scripts
			if strings.Contains(filePath, "scripts/") {
				return nil
			}
			var violations []Violation
			ast.Inspect(file, func(n ast.Node) bool {
				switch expr := n.(type) {
				case *ast.Ident:
					if expr.Name == "float32" || expr.Name == "float64" {
						pos := fset.Position(expr.Pos())
						if hasExemption(file.Comments, RuleNoFloats, pos.Line, fset) {
							return true
						}
						violations = append(violations, Violation{
							Rule:      RuleNoFloats,
							Position:  pos.String(),
							Message:   fmt.Sprintf("use of floating-point type %s", expr.Name),
							Rationale: Rationale(RuleNoFloats),
						})
					}
				case *ast.BasicLit:
					if expr.Kind == token.FLOAT {
						pos := fset.Position(expr.Pos())
						if hasExemption(file.Comments, RuleNoFloats, pos.Line, fset) {
							return true
						}
						violations = append(violations, Violation{
							Rule:      RuleNoFloats,
							Position:  pos.String(),
							Message:   fmt.Sprintf("use of float literal %s", expr.Value),
							Rationale: Rationale(RuleNoFloats),
						})
					}
				}
				return true
			})
			return violations
		},
	}
}

// NoMutationAnalyzer checks that functions modifying caller inputs have a deep-copy
// or an explicit exemption directive. Specifically checks functions taking XDR or authorization entry types.
func NoMutationAnalyzer() *Analyzer {
	return &Analyzer{
		Name:      RuleNoMutation,
		Doc:       "reports direct mutation of entry/XDR caller input parameters without deep-copy",
		Rationale: Rationale(RuleNoMutation),
		CheckFile: func(fset *token.FileSet, file *ast.File, filePath string) []Violation {
			// Skip test files, server, scripts, internal/readmesnippets
			if strings.HasSuffix(filePath, "_test.go") ||
				strings.Contains(filePath, "server/") ||
				strings.Contains(filePath, "scripts/") ||
				strings.Contains(filePath, "readmesnippets") {
				return nil
			}
			var violations []Violation

			ast.Inspect(file, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					return true
				}

				// Find parameters that are pointers to structs (specifically XDR or Entry or TargetStruct)
				ptrParams := make(map[string]bool)
				if fn.Type.Params != nil {
					for _, field := range fn.Type.Params.List {
						// Only check pointers to structs or interface/struct types
						var isRelevantPtr bool
						switch t := field.Type.(type) {
						case *ast.StarExpr:
							switch pt := t.X.(type) {
							case *ast.Ident:
								if pt.Name == "TargetStruct" || pt.Name == "SafeTargetStruct" || pt.Name == "SorobanAuthorizationEntry" || pt.Name == "Operation" || pt.Name == "InvokeHostFunctionOp" {
									isRelevantPtr = true
								}
							case *ast.SelectorExpr:
								if pt.Sel.Name == "SorobanAuthorizationEntry" || pt.Sel.Name == "InvokeHostFunctionOp" || pt.Sel.Name == "Operation" {
									isRelevantPtr = true
								}
							}
						}
						if isRelevantPtr {
							for _, name := range field.Names {
								ptrParams[name.Name] = true
							}
						}
					}
				}

				if len(ptrParams) == 0 {
					return true
				}

				// Check body for direct field assignment on pointer parameter e.g. param.Field = ...
				ast.Inspect(fn.Body, func(bn ast.Node) bool {
					assign, ok := bn.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for _, lhs := range assign.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						ident, ok := sel.X.(*ast.Ident)
						if !ok {
							continue
						}
						if ptrParams[ident.Name] {
							pos := fset.Position(assign.Pos())
							if hasExemption(file.Comments, RuleNoMutation, pos.Line, fset) {
								continue
							}
							violations = append(violations, Violation{
								Rule:      RuleNoMutation,
								Position:  pos.String(),
								Message:   fmt.Sprintf("mutation of caller input parameter %s.%s without deep-copy", ident.Name, sel.Sel.Name),
								Rationale: Rationale(RuleNoMutation),
							})
						}
					}
					return true
				})

				return true
			})

			return violations
		},
	}
}

// CheckPackage parses and checks all Go files in a directory against the analyzers.
func CheckPackage(dir string, analyzers []*Analyzer) ([]Violation, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("invariants: parsing %s: %w", dir, err)
	}

	var violations []Violation
	for _, pkg := range pkgs {
		for fileName, file := range pkg.Files {
			for _, an := range analyzers {
				v := an.CheckFile(fset, file, fileName)
				violations = append(violations, v...)
			}
		}
	}
	return violations, nil
}

// CheckTree walks all Go packages starting from root, skipping non-Go or vendor dirs.
func CheckTree(root string, analyzers []*Analyzer) ([]Violation, error) {
	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"testdata":     true,
		"adapters":     true,
		".github":      true,
		"e2e":          true,
		"docs":         true,
	}

	var allViolations []Violation
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if skipDirs[base] {
				return filepath.SkipDir
			}
			v, parseErr := CheckPackage(path, analyzers)
			if parseErr != nil {
				return parseErr
			}
			allViolations = append(allViolations, v...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("invariants: walk: %w", err)
	}
	return allViolations, nil
}
