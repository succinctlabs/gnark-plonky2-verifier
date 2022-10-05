package edwards_curve

import (
	"testing"
	"encoding/hex"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type Eddsa25519Circuit struct {
	m []frontend.Variable
	pk []frontend.Variable
	sig []frontend.Variable
}

func (circuit *Eddsa25519Circuit) Define(api frontend.API) error {
	c, err := New[Ed25519, Ed25519Scalars](api)
	if err != nil {
		return err
	}
	CheckValid(c, circuit.sig, circuit.m, circuit.pk)
	return nil
}

func TestEddsa25519(t *testing.T) {
	assert := test.NewAssert(t)

	m := "53756363696e6374204c616273"
	pk := "f7ec1c43f4de9d49556de87b86b26a98942cb078486fdb44de38b80864c39731"
	sig := "35c323757c20640a294345c89c0bfcebe3d554fdb0c7b7a0bdb72222c531b1ec849fed99a053e0f5b02dd9a25bb6eb018885526d9f583cdbde0b1e9f6329da09"

	circuit := Eddsa25519Circuit {
		m: hexToBits(m),
		pk: hexToBits(pk),
		sig: hexToBits(sig),
	}
	witness := Eddsa25519Circuit {
		m: hexToBits(m),
		pk: hexToBits(pk),
		sig: hexToBits(sig),
	}

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

func hexToBits(h string) []frontend.Variable {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	result := make([]frontend.Variable, len(b) * 8)
	for i, v := range b {
		for j := 0; j < 8; j++ {
			if (v & (1 << j)) != 0 {
				result[i*8+j] = 1
			} else {
				result[i*8+j] = 0
			}
		}
	}
	return result
}

