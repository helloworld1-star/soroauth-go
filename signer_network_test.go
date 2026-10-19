package soroauth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

type mockSigner struct {
	address string
	called  bool
}

func (m *mockSigner) Address() string {
	return m.address
}

func (m *mockSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	m.called = true
	return scVec(scBytes([]byte("sig"))), nil
}

func TestPinSignerToNetworkMainnetAndTestnet(t *testing.T) {
	kp := testKeypair(t, "network-pinning")
	inner := &mockSigner{address: kp.Address()}

	mainnetSigner, err := PinSignerToNetwork(inner, network.PublicNetworkPassphrase)
	if err != nil {
		Fatalf(t, "pinning mainnet signer: %v", err)
	}

	testnetSigner, err := PinSignerToNetwork(inner, network.TestNetworkPassphrase)
	if err != nil {
		Fatalf(t, "pinning testnet signer: %v", err)
	}

	// Build a mainnet preimage
	mainnetPreimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId: network.ID(network.PublicNetworkPassphrase),
		},
	}

	// Build a testnet preimage
	testnetPreimage := xdr.HashIdPreimage{
		Type: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{
			NetworkId: network.ID(network.TestNetworkPassphrase),
		},
	}

	payload := [32]byte{1, 2, 3}

	// 1. Mainnet signer signs mainnet preimage: success
	inner.called = false
	if _, err := mainnetSigner.Sign(context.Background(), mainnetPreimage, payload); err != nil {
		Errorf(t, "mainnet signer on mainnet preimage error = %v, want nil", err)
	}
	if !inner.called {
		Errorf(t, "mainnet signer did not delegate to inner signer")
	}

	// 2. Mainnet signer refuses testnet preimage: ErrWrongNetwork
	inner.called = false
	if _, err := mainnetSigner.Sign(context.Background(), testnetPreimage, payload); !errors.Is(err, ErrWrongNetwork) {
		Errorf(t, "mainnet signer on testnet preimage error = %v, want ErrWrongNetwork", err)
	}
	if inner.called {
		Errorf(t, "mainnet signer delegated despite network mismatch")
	}

	// 3. Testnet signer signs testnet preimage: success
	inner.called = false
	if _, err := testnetSigner.Sign(context.Background(), testnetPreimage, payload); err != nil {
		Errorf(t, "testnet signer on testnet preimage error = %v, want nil", err)
	}
	if !inner.called {
		Errorf(t, "testnet signer did not delegate to inner signer")
	}

	// 4. Testnet signer refuses mainnet preimage: ErrWrongNetwork
	inner.called = false
	if _, err := testnetSigner.Sign(context.Background(), mainnetPreimage, payload); !errors.Is(err, ErrWrongNetwork) {
		Errorf(t, "testnet signer on mainnet preimage error = %v, want ErrWrongNetwork", err)
	}
	if inner.called {
		Errorf(t, "testnet signer delegated despite network mismatch")
	}

	// 5. Source-account arm or zero preimage (no preimage) is refused explicitly
	emptyPreimage := xdr.HashIdPreimage{}
	if _, err := mainnetSigner.Sign(context.Background(), emptyPreimage, payload); !errors.Is(err, ErrWrongNetwork) {
		Errorf(t, "mainnet signer on empty preimage error = %v, want ErrWrongNetwork", err)
	}
}

func Fatalf(t testing.TB, format string, args ...any) {
	t.Helper()
	t.Fatalf(format, args...)
}

func Errorf(t testing.TB, format string, args ...any) {
	t.Helper()
	t.Errorf(format, args...)
}
