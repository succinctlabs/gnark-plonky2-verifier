package poseidon

import (
	"gnark-plonky2-verifier/field"

	"github.com/consensys/gnark/frontend"
)

type Hash = [4]field.F

type HashAPI struct {
	fieldAPI frontend.API
}

func NewHashAPI(
	fieldAPI frontend.API,
) *HashAPI {
	return &HashAPI{
		fieldAPI: fieldAPI,
	}
}

func (h *HashAPI) SelectHash(bit frontend.Variable, leftHash, rightHash Hash) Hash {
	var returnHash Hash
	for i := 0; i < 4; i++ {
		returnHash[i] = h.fieldAPI.Select(bit, leftHash[i], rightHash[i]).(field.F)
	}

	return returnHash
}

func (h *HashAPI) Lookup2Hash(b0 frontend.Variable, b1 frontend.Variable, h0, h1, h2, h3 Hash) Hash {
	var returnHash Hash

	for i := 0; i < 4; i++ {
		returnHash[i] = h.fieldAPI.Lookup2(b0, b1, h0[i], h1[i], h2[i], h3[i]).(field.F)
	}

	return returnHash
}

func (h *HashAPI) AssertIsEqualHash(h1, h2 Hash) {
	for i := 0; i < 4; i++ {
		h.fieldAPI.AssertIsEqual(h1[0], h2[0])
	}
}

func Uint64ArrayToHashArray(input [][]uint64) []Hash {
	var output []Hash
	for i := 0; i < len(input); i++ {
		output = append(output, [4]field.F{field.NewFieldElement(input[i][0]), field.NewFieldElement(input[i][1]), field.NewFieldElement(input[i][2]), field.NewFieldElement(input[i][3])})
	}
	return output
}
