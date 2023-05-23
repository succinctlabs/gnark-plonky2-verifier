package poseidon

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

type Hash = [4]field.F

type HashAPI struct {
	fieldAPI field.FieldAPI
}

func NewHashAPI(
	fieldAPI field.FieldAPI,
) *HashAPI {
	return &HashAPI{
		fieldAPI: fieldAPI,
	}
}

func (h *HashAPI) SelectHash(bit frontend.Variable, leftHash, rightHash Hash) Hash {
	var returnHash Hash
	for i := 0; i < 4; i++ {
		returnHash[i] = *h.fieldAPI.Select(bit, &leftHash[i], &rightHash[i])
	}

	return returnHash
}

func (h *HashAPI) Lookup2Hash(b0 frontend.Variable, b1 frontend.Variable, h0, h1, h2, h3 Hash) Hash {
	var returnHash Hash

	for i := 0; i < 4; i++ {
		returnHash[i] = *h.fieldAPI.Lookup2(b0, b1, &h0[i], &h1[i], &h2[i], &h3[i])
	}

	return returnHash
}

func (h *HashAPI) AssertIsEqualHash(h1, h2 Hash) {
	for i := 0; i < 4; i++ {
		h.fieldAPI.AssertIsEqual(&h1[0], &h2[0])
	}
}

func Uint64ArrayToHashArray(input [][]uint64) []Hash {
	var output []Hash
	for i := 0; i < len(input); i++ {
		output = append(output, [4]field.F{*field.NewFieldConst(input[i][0]), *field.NewFieldConst(input[i][1]), *field.NewFieldConst(input[i][2]), *field.NewFieldConst(input[i][3])})
	}
	return output
}
