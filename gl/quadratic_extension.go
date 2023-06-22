package gl

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

type QuadraticExtensionVariable [2]Variable

const W = 7
const DTH_ROOT = 18446744069414584320

func NewQuadraticExtensionVariable(x Variable, y Variable) QuadraticExtensionVariable {
	return QuadraticExtensionVariable{x, y}
}

func ZeroExtension() QuadraticExtensionVariable {
	return QuadraticExtensionVariable{Zero(), Zero()}
}

func OneExtension() QuadraticExtensionVariable {
	return QuadraticExtensionVariable{One(), Zero()}
}

// Adds two quadratic extension variables in the Goldilocks field.
func (p *Chip) AddExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.Add(a[0], b[0])
	c1 := p.Add(a[1], b[1])
	return QuadraticExtensionVariable{c0, c1}
}

// Subtracts two quadratic extension variables in the Goldilocks field.
func (p *Chip) SubExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.Sub(a[0], b[0])
	c1 := p.Sub(a[1], b[1])
	return QuadraticExtensionVariable{c0, c1}
}

// Multiplies quadratic extension variable in the Goldilocks field.
func (p *Chip) MulExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	c0 := p.Add(
		p.Mul(a[0], b[0]),
		p.Mul(
			p.Mul(NewVariableFromConst(7), a[1]),
			b[1],
		),
	)
	c1 := p.Add(
		p.Mul(a[0], b[1]),
		p.Mul(a[1], b[0]),
	)
	return QuadraticExtensionVariable{c0, c1}
}

// Multiplies quadratic extension variable in the Goldilocks field by a scalar.
func (p *Chip) ScalarMulExtension(
	a QuadraticExtensionVariable,
	b Variable,
) QuadraticExtensionVariable {
	return QuadraticExtensionVariable{
		p.Mul(a[0], b),
		p.Mul(a[1], b),
	}
}

func (p *Chip) IsZero(x QuadraticExtensionVariable) frontend.Variable {
	x0IsZero := p.api.IsZero(x[0])
	x1IsZero := p.api.IsZero(x[1])
	return p.api.Mul(x0IsZero, x1IsZero)
}

// Computes the inverse of a quadratic extension variable in the Goldilocks field.
func (p *Chip) InverseExtension(a QuadraticExtensionVariable) QuadraticExtensionVariable {
	a0IsZero := p.api.IsZero(a[0])
	a1IsZero := p.api.IsZero(a[1])
	p.api.AssertIsEqual(p.api.Mul(a0IsZero, a1IsZero), frontend.Variable(0))

	aPowRMinus1 := QuadraticExtensionVariable{
		a[0],
		p.Mul(a[1], NewVariableFromConst(DTH_ROOT)),
	}
	aPowR := p.MulExtension(aPowRMinus1, a)
	return p.ScalarMulExtension(aPowRMinus1, p.Inverse(aPowR[0]))
}

// Divides two quadratic extension variables in the Goldilocks field.
func (p *Chip) DivExtension(a, b QuadraticExtensionVariable) QuadraticExtensionVariable {
	return p.MulExtension(a, p.InverseExtension(b))
}

func (p *Chip) ExpU64Extension(
	a QuadraticExtensionVariable,
	exponent uint64,
) QuadraticExtensionVariable {
	switch exponent {
	case 0:
		return QuadraticExtensionVariable{NewVariableFromConst(1), NewVariableFromConst(0)}
	case 1:
		return a
	case 2:
		return p.MulExtension(a, a)
	default:
	}

	current := a
	product := QuadraticExtensionVariable{NewVariableFromConst(1), NewVariableFromConst(0)}

	for i := 0; i < bits.Len64(exponent); i++ {
		if i != 0 {
			current = p.MulExtension(current, current)
		}
		if (exponent >> i & 1) != 0 {
			product = p.MulExtension(product, current)
		}
	}

	return product
}

// Reduces a list of terms with a scalar power.
func (p *Chip) ReduceWithPowers(
	terms []QuadraticExtensionVariable,
	scalar QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	sum := QuadraticExtensionVariable{NewVariableFromConst(0), NewVariableFromConst(0)}
	for i := len(terms) - 1; i >= 0; i-- {
		sum = p.AddExtension(
			p.MulExtension(
				sum,
				scalar,
			),
			terms[i],
		)
	}
	return sum
}

func (p *Chip) Lookup(
	b frontend.Variable,
	x, y QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	c0 := p.api.Select(b, x[0].value, y[0].value)
	c1 := p.api.Select(b, x[1].value, y[1].value)
	return QuadraticExtensionVariable{NewVariable(c0), NewVariable(c1)}
}

func (p *Chip) Lookup2(
	b0 frontend.Variable,
	b1 frontend.Variable,
	qe0, qe1, qe2, qe3 QuadraticExtensionVariable,
) QuadraticExtensionVariable {
	c0 := p.Lookup(b0, qe0, qe1)
	c1 := p.Lookup(b0, qe2, qe3)
	return p.Lookup(b1, c0, c1)
}
