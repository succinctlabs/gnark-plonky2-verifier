package plonky2_verifier

import (
	"fmt"
	"gnark-plonky2-verifier/field"

	"github.com/consensys/gnark/frontend"
)

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

func (h *HashAPI) SelectHash(bit frontend.Variable, leftHash, rightHash field.Hash) field.Hash {
	var returnHash field.Hash
	for i := 0; i < 4; i++ {
		returnHash[i] = h.fieldAPI.Select(bit, leftHash[i], rightHash[i]).(field.F)
	}

	return returnHash
}

func (h *HashAPI) Lookup2Hash(b0 frontend.Variable, b1 frontend.Variable, h0, h1, h2, h3 field.Hash) field.Hash {
	var returnHash field.Hash

	for i := 0; i < 4; i++ {
		returnHash[i] = h.fieldAPI.Lookup2(b0, b1, h0[i], h1[i], h2[i], h3[i]).(field.F)
	}

	return returnHash
}

func (h *HashAPI) AssertIsEqualHash(h1, h2 field.Hash) {
	for i := 0; i < 4; i++ {
		h.fieldAPI.AssertIsEqual(h1[0], h2[0])
	}
}

func (h *HashAPI) PrintHash(hash field.Hash) {
	for i := 0; i < 4; i++ {
		fmt.Println("field.Hash Limb", i)
		h.fieldAPI.Println(hash[i])
	}
}
