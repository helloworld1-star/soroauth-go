package invariants

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

func TestAnalyzers_Fixtures(t *testing.T) {
	tests := []struct {
		name        string
		analyzer    *Analyzer
		violating   string
		compliant   string
		expectedMsg string
	}{
		{
			name:        "no-panic",
			analyzer:    NoPanicAnalyzer(),
			violating:   "violating_panic.go",
			compliant:   "compliant_panic.go",
			expectedMsg: "use of panic in non-test code",
		},
		{
			name:        "no-logging",
			analyzer:    NoLoggingAnalyzer(),
			violating:   "violating_logging.go",
			compliant:   "compliant_logging.go",
			expectedMsg: "forbidden logging import",
		},
		{
			name:        "no-math-rand",
			analyzer:    NoMathRandAnalyzer(),
			violating:   "violating_mathrand.go",
			compliant:   "compliant_mathrand.go",
			expectedMsg: "use of math/rand is forbidden",
		},
		{
			name:        "no-floats",
			analyzer:    NoFloatsAnalyzer(),
			violating:   "violating_floats.go",
			compliant:   "compliant_floats.go",
			expectedMsg: "use of floating-point type",
		},
		{
			name:        "no-mutation",
			analyzer:    NoMutationAnalyzer(),
			violating:   "violating_mutation.go",
			compliant:   "compliant_mutation.go",
			expectedMsg: "mutation of caller input parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			violatingPath := filepath.Join("testdata", tt.violating)
			violFile, err := parser.ParseFile(fset, violatingPath, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", violatingPath, err)
			}
			violations := tt.analyzer.CheckFile(fset, violFile, violatingPath)
			if len(violations) == 0 {
				t.Fatalf("expected violation in %s, got none", violatingPath)
			}
			if violations[0].Rationale == "" {
				t.Errorf("violation missing rationale")
			}
			if violations[0].Position == "" {
				t.Errorf("violation missing position")
			}

			// Compliant fixture check
			fsetComp := token.NewFileSet()
			compliantPath := filepath.Join("testdata", tt.compliant)
			compFile, err := parser.ParseFile(fsetComp, compliantPath, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("failed to parse %s: %v", compliantPath, err)
			}
			compViolations := tt.analyzer.CheckFile(fsetComp, compFile, compliantPath)
			if len(compViolations) != 0 {
				t.Fatalf("expected 0 violations in compliant fixture %s, got %d: %v", compliantPath, len(compViolations), compViolations)
			}
		})
	}
}
