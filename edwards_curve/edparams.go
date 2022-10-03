package edwards_curve

import (
	"math/big"
)

var (
	qEd25519, rEd25519 *big.Int
)

func init() {
	// https://neuromancer.sk/std/other/Ed25519
	qEd25519, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	n, _ := new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
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

type Ed25519Scalars struct{}

func (fp Ed25519Scalars) NbLimbs() uint     { return 4 }
func (fp Ed25519Scalars) BitsPerLimb() uint { return 64 }
func (fp Ed25519Scalars) IsPrime() bool     { return true }
func (fp Ed25519Scalars) Modulus() *big.Int { return rEd25519 }

