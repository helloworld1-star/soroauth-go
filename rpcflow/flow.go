package rpcflow


// FlowPhase represents a stage in the SignAndSubmit flow.
type FlowPhase string

const (
	FlowPhaseRecord  FlowPhase = "record"
	FlowPhaseSigning FlowPhase = "signing"
	FlowPhaseEnforce FlowPhase = "enforce"
	FlowPhaseSubmit  FlowPhase = "submit"
	FlowPhasePoll    FlowPhase = "poll"
)

// FlowEvent carries structural metadata about a flow phase.
type FlowEvent struct {
	Phase             FlowPhase
	AuthParticipants  int
	MinResourceFee    int64
	ResourceFeeDiff   int64
}

// FlowHook defines the interface for receiving flow events.
type FlowHook interface {
	Event(ctx context.Context, e FlowEvent) error
}

// FlowHookKey is the context key for storing a FlowHook.
type FlowHookKey struct{}
