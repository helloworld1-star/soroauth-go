package opentelemetry

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

type mockRPCClient struct {
	sims   []rpc.SimulateTransactionResponse
	simIdx int
}

func (m *mockRPCClient) SimulateTransaction(_ context.Context, _ rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error) {
	if m.simIdx < len(m.sims) {
		resp := m.sims[m.simIdx]
		m.simIdx++
		return resp, nil
	}
	return m.sims[len(m.sims)-1], nil
}

func (m *mockRPCClient) GetLatestLedger(context.Context) (rpc.GetLatestLedgerResponse, error) {
	return rpc.GetLatestLedgerResponse{Sequence: 100}, nil
}

func (m *mockRPCClient) SendTransaction(context.Context, rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error) {
	return rpc.SendTransactionResponse{Hash: "deadbeef", Status: "PENDING"}, nil
}

func (m *mockRPCClient) PollTransaction(context.Context, string) (rpc.GetTransactionResponse, error) {
	return rpc.GetTransactionResponse{
		TransactionDetails: rpc.TransactionDetails{
			Status: rpc.TransactionStatusSuccess,
			Ledger: 101,
		},
	}, nil
}

func testKey(t testing.TB, seed string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestOpenTelemetryFullFlowTraceAndSanitization(t *testing.T) {
	payer := testKey(t, "otel-payer")
	signer := testKey(t, "otel-signer")

	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}

	address, err := soroauth.ParseAddress(signer.Address())
	if err != nil {
		t.Fatal(err)
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     1,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	entryEncoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatal(err)
	}

	data := xdr.SorobanTransactionData{}
	dataEncoded, err := xdr.MarshalBase64(data)
	if err != nil {
		t.Fatal(err)
	}

	authList := []string{entryEncoded}
	simResp := rpc.SimulateTransactionResponse{
		TransactionDataXDR: dataEncoded,
		MinResourceFee:     1000,
		Results:            []rpc.SimulateHostFunctionResult{{AuthXDR: &authList}},
	}
	simRespEnforce := rpc.SimulateTransactionResponse{
		TransactionDataXDR: dataEncoded,
		MinResourceFee:     5500,
		Results:            []rpc.SimulateHostFunctionResult{{AuthXDR: &authList}},
	}

	mClient := &mockRPCClient{
		sims: []rpc.SimulateTransactionResponse{simResp, simRespEnforce},
	}

	params := rpcflow.Params{
		Source: &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operation: txnbuild.InvokeHostFunction{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
			SourceAccount: payer.Address(),
		},
		Signers:           []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: network.TestNetworkPassphrase,
		Client:            mClient,
	}

	hook, tracer := NewFlowHook()
	ctx := context.WithValue(context.Background(), rpcflow.FlowHookKey{}, hook)

	sub, err := rpcflow.SignAndSubmit(ctx, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if sub.Hash != "deadbeef" {
		t.Errorf("expected hash deadbeef, got %s", sub.Hash)
	}

	spanNames := []string{}
	for _, s := range tracer.Spans {
		spanNames = append(spanNames, s.Name)
	}

	expectedSpans := []string{
		"soroauth.flow.record",
		"soroauth.flow.signing",
		"soroauth.flow.enforce",
		"soroauth.flow.submit_and_poll",
	}

	for _, exp := range expectedSpans {
		found := false
		for _, n := range spanNames {
			if n == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected span %s in trace, got spans: %v", exp, spanNames)
		}
	}

	var feeDiffFound bool
	for _, s := range tracer.Spans {
		if s.Name == "soroauth.flow.enforce" {
			if diff, ok := s.Attributes["soroauth.resource_fee_diff"]; ok {
				if diff == int64(4500) {
					feeDiffFound = true
				}
			}
		}
	}
	if !feeDiffFound {
		t.Errorf("resource_fee_diff attribute of 4500 not found on enforce span")
	}

	for _, s := range tracer.Spans {
		for k, val := range s.Attributes {
			strVal := strings.ToLower(fmt.Sprintf("%v", val))
			keyLower := strings.ToLower(k)
			if strings.Contains(keyLower, "secret") || strings.Contains(keyLower, "sig") || strings.Contains(keyLower, "entry") {
				t.Errorf("span attribute key %q contains forbidden substring", k)
			}
			if strings.Contains(strVal, "secret") || strings.Contains(strVal, "private") {
				t.Errorf("span attribute value for %q contains sensitive content", k)
			}
		}
	}
}
