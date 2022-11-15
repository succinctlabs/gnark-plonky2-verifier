package plonky2_verifier

import (
	"fmt"
	. "gnark-ed25519/field"

	"github.com/consensys/gnark/frontend"
)

func SelectHash(fieldAPI frontend.API, bit frontend.Variable, leftHash, rightHash Hash) Hash {
	var returnHash Hash
	for i := 0; i < 4; i++ {
		returnHash[i] = fieldAPI.Select(bit, leftHash[i], rightHash[i]).(F)
	}

	return returnHash
}

func Lookup2Hash(fieldAPI frontend.API, b0 frontend.Variable, b1 frontend.Variable, h0, h1, h2, h3 Hash) Hash {
	var returnHash Hash

	for i := 0; i < 4; i++ {
		returnHash[i] = fieldAPI.Lookup2(b0, b1, h0[i], h1[i], h2[i], h3[i]).(F)
	}

	return returnHash
}

func AssertIsEqualHash(fieldAPI frontend.API, h1, h2 Hash) {
	for i := 0; i < 4; i++ {
		fieldAPI.AssertIsEqual(h1[0], h2[0])
	}
}

func PrintHash(f frontend.API, h Hash) {
	for i := 0; i < 4; i++ {
		fmt.Println("Hash Limb", i)
		f.Println(h[i])
	}
}
