package fixtures

// violating_panic.go violates no-panic
func ViolatingPanic() {
	panic("unexpected error")
}
