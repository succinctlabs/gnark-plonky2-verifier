// This package implements efficient Golidlocks arithmetic operations within Gnark. We do not use
// the emulated field arithmetic API, because it is too slow for our purposes. Instead, we use
// an efficient reduction method that leverages the fact that the modulus is a simple
// linear combination of powers of two.
package gl

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/field/goldilocks"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

// The multiplicative group generator of the field.
var MULTIPLICATIVE_GROUP_GENERATOR = goldilocks.NewElement(7)

// The two adicity of the field.
var TWO_ADICITY = uint64(32)

// The power of two generator of the field.
var POWER_OF_TWO_GENERATOR = goldilocks.NewElement(1753635133440165772)

// The modulus of the field.
var MODULUS = emulated.Goldilocks{}.Modulus()

// A type alias used to represent Goldilocks field elements.
type FieldElement frontend.Variable

func init() {
	solver.RegisterHint(MulAddHint)
}

// The chip used for Goldilocks field operations.
type Chip struct {
	api frontend.API
}

// Creates a new Goldilocks chip.
func NewChip(api frontend.API) *Chip {
	return &Chip{api: api}
}

// Adds two field elements such that x + y = z within the Golidlocks field.
func (p *Chip) Add(a FieldElement, b FieldElement) FieldElement {
	return p.MulAdd(a, frontend.Variable(1), b)
}

// Multiplies two field elements such that x * y = z within the Golidlocks field.
func (p *Chip) Mul(a FieldElement, b FieldElement) FieldElement {
	return p.MulAdd(a, b, frontend.Variable(0))
}

// Multiplies two field elements and adds a field element such that x * y + z = c within the
// Golidlocks field.
func (p *Chip) MulAdd(a FieldElement, b FieldElement, c FieldElement) FieldElement {
	result, err := p.api.Compiler().NewHint(MulAddHint, 2, a, b, c)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	lhs := p.api.Mul(a, b)
	lhs = p.api.Add(lhs, c)
	rhs := p.api.Add(p.api.Mul(quotient, MODULUS), remainder)
	p.api.AssertIsEqual(lhs, rhs)

	p.RangeCheck(quotient)
	p.RangeCheck(remainder)
	return remainder
}

// The hint used to compute MulAdd.
func MulAddHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 3 {
		panic("GoldilocksMulAddHint expects 3 input operands")
	}

	for _, operand := range inputs {
		if operand.Cmp(MODULUS) >= 0 {
			panic(fmt.Sprintf("%s is not in the field", operand.String()))
		}
	}

	product := new(big.Int).Mul(inputs[0], inputs[1])
	sum := new(big.Int).Add(product, inputs[2])
	quotient := new(big.Int).Div(sum, MODULUS)
	remainder := new(big.Int).Rem(sum, MODULUS)

	results[0] = quotient
	results[1] = remainder

	return nil
}

// Range checks a field element x to be less than the Golidlocks modulus 2 ^ 64 - 2 ^ 32 + 1.
func (p *Chip) RangeCheck(x FieldElement) {
	// The Goldilocks' modulus is 2^64 - 2^32 + 1, which is:
	//
	// 		1111111111111111111111111111111100000000000000000000000000000001
	//
	// in big endian binary. This function will first verify that x is at most 64 bits wide. Then it
	// checks that if the bits[0:31] (in big-endian) are all 1, then bits[32:64] are all zero.

	// First decompose x into 64 bits.  The bits will be in little-endian order.
	bits := bits.ToBinary(p.api, x, bits.WithNbDigits(64))

	// Those bits should compose back to x.
	reconstructedX := frontend.Variable(0)
	c := uint64(1)
	for i := 0; i < 64; i++ {
		reconstructedX = p.api.Add(reconstructedX, p.api.Mul(bits[i], c))
		c = c << 1
		p.api.AssertIsBoolean(bits[i])
	}
	p.api.AssertIsEqual(x, reconstructedX)

	mostSigBits32Sum := frontend.Variable(0)
	for i := 32; i < 64; i++ {
		mostSigBits32Sum = p.api.Add(mostSigBits32Sum, bits[i])
	}

	leastSigBits32Sum := frontend.Variable(0)
	for i := 0; i < 32; i++ {
		leastSigBits32Sum = p.api.Add(leastSigBits32Sum, bits[i])
	}

	// If mostSigBits32Sum < 32, then we know that:
	//
	// 		x < (2^63 + ... + 2^32 + 0 * 2^31 + ... + 0 * 2^0)
	//
	// which equals to 2^64 - 2^32. So in that case, we don't need to do any more checks. If
	// mostSigBits32Sum == 32, then we need to check that x == 2^64 - 2^32 (max GL value).
	shouldCheck := p.api.IsZero(p.api.Sub(mostSigBits32Sum, 32))
	p.api.AssertIsEqual(
		p.api.Select(
			shouldCheck,
			leastSigBits32Sum,
			frontend.Variable(0),
		),
		frontend.Variable(0),
	)
}
