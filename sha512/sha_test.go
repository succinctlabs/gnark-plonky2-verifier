package sha512

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Sha512Circuit struct {
	in []frontend.Variable `gnark:"in"`
	out []frontend.Variable `gnark:"out"`
}

func (circuit *Sha512Circuit) Define(api frontend.API) error {
	res := Sha512(api, circuit.in)
	for i := 0; i < 512; i++ {
		api.AssertIsEqual(res[i], circuit.out[i])
	}
	return nil
}

func TestSha512(t *testing.T) {
	assert := test.NewAssert(t)
	in := toBytes("Succinct Labs")
	out := toBytes("503ace098aa03f6feec1b5df0a38aee923f744a775508bc81f2b94ad139be297c2e8cd8c44af527b5d3f017a7fc929892c896604047e52e3f518924f52bff0dc")
	circuit := Sha512Circuit {
		in: toVariables(make([]byte, len(in))),
		out: toVariables(make([]byte, len(out))),
	}
	witness := Sha512Circuit {
		in: toVariables(in),
		out: toVariables(out),
	}
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func toVariables(arr []byte) []frontend.Variable {
	result := make([]frontend.Variable, len(arr))
	for i, v := range arr {
		result[i] = v
	}
	return result
}

func toBytes(s string) []byte {
	return []byte(s)
}
