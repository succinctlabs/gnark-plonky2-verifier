package plonky2_verifier

import (
	"fmt"
	"math/bits"
)

// Computes `log_2(n)`, panicking if `n` is not a power of two.
func log2Strict(n uint) int {
	res := bits.TrailingZeros(n)
	if n>>res != 1 {
		panic(fmt.Sprintf("Not a power of two: %d", n))
	}
	return res
}
