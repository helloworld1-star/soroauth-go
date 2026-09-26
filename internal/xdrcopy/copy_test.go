package xdrcopy

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
	xdrcodec "github.com/stellar/go-xdr/xdr3"
	"github.com/stretchr/testify/require"
)

func (u underConsume) EncodeTo(e *xdrcodec.Encoder) error {
	_, err := e.EncodeUint(u.V)
	return err
}

func (u *underConsume) DecodeFrom(_ *xdrcodec.Decoder, _ uint) (int, error) {
	return 0, nil
}

type underConsume struct{ V uint32 }

var _ xdr.EncoderTo = (*underConsume)(nil)

var _ xdr.DecoderFrom = (*underConsume)(nil)

func FuzzCopy(f *testing.F) {
	// Use a simple XDR type for fuzzing.
	val := xdr.ScVal{Type: xdr.ScValTypeScvI64, I64: new(xdr.Int64)}
	bytes, _ := val.MarshalBinary()
	f.Add(bytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.ScVal
		if err := entry.UnmarshalBinary(data); err != nil {
			return
		}

		copied, err := Copy(entry)
		require.NoError(t, err)
		require.Equal(t, entry, copied)
	})
}
