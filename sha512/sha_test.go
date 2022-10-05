package sha512

import (
	"testing"
	"encoding/hex"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark-crypto/ecc"
)

type Sha512Circuit struct {
	in []frontend.Variable `gnark:"in"`
	out []frontend.Variable `gnark:"out"`
}

func (circuit *Sha512Circuit) Define(api frontend.API) error {
	res := Sha512Bits(api, circuit.in)
	if len(res) != 512 { panic("bad length") }
	for i := 0; i < 512; i++ {
		api.AssertIsEqual(res[i], circuit.out[i])
	}
	return nil
}

var testCurve = ecc.BN254

func TestSha512(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(input, output string) {
		in := toBytes(input)
		out, err := hex.DecodeString(output)
		if err != nil { panic(err) }
		if len(out) != 512 / 8 { panic("bad output length") }

		circuit := Sha512Circuit {
			in: toBits(in),
			out: toBits(out),
		}
		witness := Sha512Circuit {
			in: toBits(in),
			out: toBits(out),
		}
		err = test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}

	testCase("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
	testCase("Succinct Labs", "503ace098aa03f6feec1b5df0a38aee923f744a775508bc81f2b94ad139be297c2e8cd8c44af527b5d3f017a7fc929892c896604047e52e3f518924f52bff0dc")
}

func toBits(arr []byte) []frontend.Variable {
	result := make([]frontend.Variable, len(arr) * 8)
	for i, v := range arr {
		for j := 0; j < 8; j++ {
			if (v & (1 << (7-j))) != 0 {
				result[i*8+j] = 1
			} else {
				result[i*8+j] = 0
			}
		}
	}
	return result
}

func toBytes(s string) []byte {
	return []byte(s)
}
