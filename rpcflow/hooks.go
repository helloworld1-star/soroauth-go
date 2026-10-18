package rpcflow

import (
	"context"
	"time"
)

// FlowHookKey is the context key type used to store and retrieve a FlowHook.
type FlowHookKey struct{}

// FlowPhase identifies a stage in the SignAndSubmit flow.
type FlowPhase string

const (
	FlowPhaseRecord  FlowPhase = "record"
	FlowPhaseSigning FlowPhase = "signing"
	FlowPhaseEnforce FlowPhase = "enforce"
	FlowPhaseSubmit  FlowPhase = "submit"
	FlowPhasePoll    FlowPhase = "poll"
)

// FlowEvent carries structural telemetry data for each phase of the flow.
// No secret material, entry, or signature is ever included.
type FlowEvent struct {
	Phase            FlowPhase
	AuthParticipants int
	MinResourceFee   int64
	ResourceFeeDiff  int64
	Duration         time.Duration
	Error            error
}

// FlowHook receives lifecycle events during SignAndSubmit.
type FlowHook interface {
	Event(ctx context.Context, e FlowEvent) error
}
