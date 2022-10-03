package edwards_curve

import (
	"math/big"
)

var (
	qEd25519, rEd25519 *big.Int
)

func init() {
	// https://neuromancer.sk/std/other/Ed25519
	qEd25519 = newBigInt("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
	n := newBigInt("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	// TODO: is this ok?
	// h := big.NewInt(8)
	// rEd25519 = new(big.Int).Mul(n, h)
	rEd25519 = n
}

type Ed25519 struct{}

func (fp Ed25519) NbLimbs() uint     { return 4 }
func (fp Ed25519) BitsPerLimb() uint { return 64 }
func (fp Ed25519) IsPrime() bool     { return true }
func (fp Ed25519) Modulus() *big.Int { return qEd25519 }
func (fp Ed25519) Generator() (*big.Int, *big.Int) {
	return newBigInt("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"),
		newBigInt("6666666666666666666666666666666666666666666666666666666666666658")
}

type Ed25519Scalars struct{}

func (fp Ed25519Scalars) NbLimbs() uint     { return 4 }
func (fp Ed25519Scalars) BitsPerLimb() uint { return 64 }
func (fp Ed25519Scalars) IsPrime() bool     { return true }
func (fp Ed25519Scalars) Modulus() *big.Int { return rEd25519 }

