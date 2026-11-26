package fixtures

import (
	"math/rand"
)

// violating_mathrand.go violates no-math-rand
func ViolatingMathRand() int {
	return rand.Intn(100)
}
