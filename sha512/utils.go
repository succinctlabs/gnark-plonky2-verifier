package sha512

import ("math/big")

func newBigInt(s string) *big.Int {
	result, success := new(big.Int).SetString(s, 16)
	if !success {
		panic("invalid bigint")
	}
	return result
}

func newBigIntBase10(s string) *big.Int {
	result, success := new(big.Int).SetString(s, 10)
	if !success {
		panic("invalid bigint")
	}
	return result
}