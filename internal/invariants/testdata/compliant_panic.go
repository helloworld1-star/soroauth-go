package fixtures

// compliant_panic.go satisfies no-panic via exemption directive with rationale
func CompliantPanic() {
	// invariant-allow: no-panic unreachable protocol state in test harness
	panic("allowed unreachable panic")
}
