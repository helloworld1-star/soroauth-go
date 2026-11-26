package fixtures

type SafeTargetStruct struct {
	Value int
}

// compliant_mutation.go satisfies no-mutation via exemption directive
func CompliantMutation(s *SafeTargetStruct) {
	// invariant-allow: no-mutation in-place builder mutation on newly allocated object
	s.Value = 100
}
