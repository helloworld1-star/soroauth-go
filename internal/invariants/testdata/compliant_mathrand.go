package fixtures

import (
	// invariant-allow: no-math-rand deterministic simulation seed
	"math/rand"
)

// compliant_mathrand.go satisfies no-math-rand via exemption
func CompliantMathRand() int {
	return rand.Intn(10)
}
