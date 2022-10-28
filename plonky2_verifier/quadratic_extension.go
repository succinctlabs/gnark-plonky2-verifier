package plonky2_verifier

import (
	. "gnark-ed25519/field"

	"github.com/consensys/gnark/frontend"
)

type QuadraticExtensionAPI struct {
	field frontend.API

	W             F
	DTH_ROOT      F
	ZERO_F        F
	DEGREE_BITS_F F

	ONE            QuadraticExtension
	DEGREE_BITS_QE QuadraticExtension
}

func NewQuadraticExtensionAPI(field frontend.API, degreeBits uint64) *QuadraticExtensionAPI {
	// TODO:  Should degreeBits be verified that it fits within the field?

	return &QuadraticExtensionAPI{
		field: field,

		W:             NewFieldElement(7),
		DTH_ROOT:      NewFieldElement(18446744069414584320),
		ZERO_F:        NewFieldElement(0),
		DEGREE_BITS_F: NewFieldElement(degreeBits),

		ONE:            QuadraticExtension{NewFieldElement(1), NewFieldElement(0)},
		DEGREE_BITS_QE: QuadraticExtension{NewFieldElement(degreeBits), NewFieldElement(0)},
	}
}

func (c *QuadraticExtensionAPI) SquareExtension(a QuadraticExtension) QuadraticExtension {
	return c.MulExtension(a, a)
}

func (c *QuadraticExtensionAPI) MulExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.field.Add(c.field.Mul(a[0], b[0]).(F), c.field.Mul(c.W, a[1], b[1])).(F)
	c_1 := c.field.Add(c.field.Mul(a[0], b[1]).(F), c.field.Mul(a[1], b[0])).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) AddExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.field.Add(a[0], b[0]).(F)
	c_1 := c.field.Add(a[1], b[1]).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) SubExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	c_0 := c.field.Sub(a[0], b[0]).(F)
	c_1 := c.field.Sub(a[1], b[1]).(F)
	return QuadraticExtension{c_0, c_1}
}

func (c *QuadraticExtensionAPI) DivExtension(a QuadraticExtension, b QuadraticExtension) QuadraticExtension {
	return c.MulExtension(a, c.InverseExtension(b))
}

// TODO: Instead of calculating the inverse within the circuit, can witness the
// inverse and assert that a_inverse * a = 1.  Should reduce # of constraints.
func (c *QuadraticExtensionAPI) InverseExtension(a QuadraticExtension) QuadraticExtension {
	// First assert that a doesn't have 0 value coefficients
	a0_is_zero := c.field.IsZero(a[0])
	a1_is_zero := c.field.IsZero(a[1])

	// assert that a0_is_zero OR a1_is_zero == false
	c.field.AssertIsEqual(c.field.Mul(a0_is_zero, a1_is_zero).(F), c.ZERO_F)

	a_pow_r_minus_1 := QuadraticExtension{a[0], c.field.Mul(a[1], c.DTH_ROOT).(F)}
	a_pow_r := c.MulExtension(a_pow_r_minus_1, a)
	return c.ScalarMulExtension(a_pow_r_minus_1, c.field.Inverse(a_pow_r[0]).(F))
}

func (c *QuadraticExtensionAPI) ScalarMulExtension(a QuadraticExtension, scalar F) QuadraticExtension {
	return QuadraticExtension{c.field.Mul(a[0], scalar).(F), c.field.Mul(a[1], scalar).(F)}
}
