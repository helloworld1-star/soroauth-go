package fixtures

type TargetStruct struct {
	Value int
}

// violating_mutation.go violates no-mutation
func ViolatingMutation(s *TargetStruct) {
	s.Value = 42
}
