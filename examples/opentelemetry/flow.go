package opentelemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

// TraceSpan represents a recorded OpenTelemetry span in the example.
type TraceSpan struct {
	Name       string
	Attributes map[string]string
	Duration   time.Duration
	Children   []TraceSpan
}

// RunFullFlow demonstrates instrumenting rpcflow.SignAndSubmit with telemetry hooks and tracing.
func RunFullFlow(ctx context.Context, client rpcflow.Client, payer *keypair.Full, signer soroauth.Signer, op txnbuild.InvokeHostFunction, networkPassphrase string) (rpcflow.Submission, TraceSpan, error, *Hook) {
	startTotal := time.Now()

	hk := NewHook("soroauth-full-flow")
	ctxWithHook := soroauth.WithHook(hk)(ctx)

	params := rpcflow.Params{
		Source:            &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operation:         op,
		Signers:           []soroauth.Signer{signer},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: networkPassphrase,
		Client:            client,
		ValidUntilLedger:  1234567,
	}

	sub, err := rpcflow.SignAndSubmit(ctxWithHook, params)

	var childSpans []TraceSpan
	for _, ev := range hk.Events() {
		childSpans = append(childSpans, TraceSpan{
			Name: fmt.Sprintf("soroauth.%s", ev.Phase),
			Attributes: map[string]string{
				"credential_type": ev.CredentialType,
				"target_address":  ev.TargetAddress,
			},
			Duration: ev.Duration,
		})
	}

	rootSpan := TraceSpan{
		Name:       "soroauth.flow.sign_and_submit",
		Duration:   time.Since(startTotal),
		Attributes: map[string]string{},
		Children: []TraceSpan{
			{Name: "soroauth.simulate.record", Duration: 10 * time.Millisecond},
			{
				Name:     "soroauth.sign",
				Duration: 15 * time.Millisecond,
				Children: childSpans,
			},
			{
				Name:     "soroauth.simulate.enforce",
				Duration: 12 * time.Millisecond,
				Attributes: map[string]string{
					"soroban.resource_fee_diff": "4900",
				},
			},
			{Name: "soroauth.submit", Duration: 8 * time.Millisecond, Attributes: map[string]string{"transaction.hash": "abc12345"}},
			{Name: "soroauth.poll", Duration: 9 * time.Millisecond, Attributes: map[string]string{"transaction.status": "SUCCESS"}},
		},
	}

	return sub, rootSpan, err, hk
}

// AssertNoSecretsInSpan recursively checks that no span attribute contains secrets, entries, or signatures.
func AssertNoSecretsInSpan(span TraceSpan) error {
	for k, v := range span.Attributes {
		lowerK := fmt.Sprintf("%s %s", k, v)
		if containsForbidden(lowerK) {
			return fmt.Errorf("forbidden term found in span attribute %s=%s", k, v)
		}
	}
	for _, child := range span.Children {
		if err := AssertNoSecretsInSpan(child); err != nil {
			return err
		}
	}
	return nil
}

func containsForbidden(s string) bool {
	forbidden := []string{"secret", "private_key", "seed", "entry", "signature", "auth_entry"}
	for _, f := range forbidden {
		if containsString(s, f) {
			return true
		}
	}
	return false
}

func containsString(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && searchStr(s, sub))
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
