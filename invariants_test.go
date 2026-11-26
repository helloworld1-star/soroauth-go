package soroauth

import (
	"testing"

	"github.com/soroauth/soroauth-go/internal/invariants"
)

// TestRepositoryInvariants verifies that the entire repository satisfies the
// five core architectural invariants:
// 1. No mutation of caller input without deep copy
// 2. No logging in library code
// 3. No panic outside tests
// 4. No math/rand
// 5. No floats
func TestRepositoryInvariants(t *testing.T) {
	analyzers := invariants.AllAnalyzers()
	violations, err := invariants.CheckTree(".", analyzers)
	if err != nil {
		t.Fatalf("checking repository invariants: %v", err)
	}

	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("%s", v.String())
		}
		t.Fatalf("found %d invariant violations across repository", len(violations))
	}
}
