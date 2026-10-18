package opentelemetry

import (
	"context"
	"fmt"

	"github.com/soroauth/soroauth-go/rpcflow"
)

// Span represents a recorded span in our OpenTelemetry trace.
type Span struct {
	Name       string
	Attributes map[string]any
}

// TracerStub represents an OpenTelemetry Tracer.
type TracerStub struct {
	Spans []Span
}

// FlowHook bridges rpcflow.FlowHook to record spans matching the full flow.
type FlowHook struct {
	Tracer *TracerStub
}

// NewFlowHook creates a FlowHook recording into a new TracerStub.
func NewFlowHook() (*FlowHook, *TracerStub) {
	t := &TracerStub{}
	return &FlowHook{Tracer: t}, t
}

// Event implements rpcflow.FlowHook, translating flow events into OTel-style spans.
func (fh *FlowHook) Event(ctx context.Context, e rpcflow.FlowEvent) error {
	if fh.Tracer == nil {
		return nil
	}

	var name string
	attrs := map[string]any{}

	switch e.Phase {
	case rpcflow.FlowPhaseRecord:
		name = "soroauth.flow.record"
		attrs["soroauth.pass"] = "record"
	case rpcflow.FlowPhaseSigning:
		name = "soroauth.flow.signing"
		attrs["soroauth.auth_participants"] = e.AuthParticipants
	case rpcflow.FlowPhaseEnforce:
		name = "soroauth.flow.enforce"
		attrs["soroauth.pass"] = "enforce"
		attrs["soroauth.min_resource_fee"] = e.MinResourceFee
		attrs["soroauth.resource_fee_diff"] = e.ResourceFeeDiff
	case rpcflow.FlowPhaseSubmit, rpcflow.FlowPhasePoll:
		name = "soroauth.flow.submit_and_poll"
		attrs["soroauth.action"] = string(e.Phase)
	default:
		name = fmt.Sprintf("soroauth.flow.%s", e.Phase)
	}

	fh.Tracer.Spans = append(fh.Tracer.Spans, Span{
		Name:       name,
		Attributes: attrs,
	})
	return nil
}
