package edwards_curve

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func New[T, S emulated.FieldParams](api frontend.API) (*Curve[T, S], error) {
	var t T
	var s S
	var gxb, gyb *big.Int
	var A, D *big.Int
	_, is_25519_t := any(t).(Ed25519)
	_, is_25519_s := any(s).(Ed25519Scalars)
	if is_25519_t && is_25519_s {
		// https://neuromancer.sk/std/other/Ed25519
		gxb = newBigInt("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A")
		gyb = newBigInt("6666666666666666666666666666666666666666666666666666666666666658")
		A = newBigInt("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec")
		D = newBigInt("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")
	} else {
		return nil, fmt.Errorf("unknown curve")
	}
	return newCurve[T, S](
		api,
		emulated.NewElement[T](A),
		emulated.NewElement[T](D),
		emulated.NewElement[T](gxb),
		emulated.NewElement[T](gyb))
}

func newBigInt(s string) *big.Int {
	result, success := new(big.Int).SetString(s, 16)
	if !success {
		panic("invalid bigint")
	}
	return result
}

// TODO: could also have a type constraint for curve parameters (fields,
// equation and generator). But for now we don't do arbitrary curves.

type Curve[T, S emulated.FieldParams] struct {
	a emulated.Element[T]
	d emulated.Element[T]

	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi frontend.API
	// scalarApi is the api for scalar operations
	scalarApi frontend.API

	g AffinePoint[T]
}

func (c *Curve[T, S]) Generator() AffinePoint[T] {
	return c.g
}

func newCurve[T, S emulated.FieldParams](api frontend.API, a, d, Gx, Gy emulated.Element[T]) (*Curve[T, S], error) {
	ba, err := emulated.NewField[T](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[S](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	return &Curve[T, S]{
		a: a,
		d: d,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: AffinePoint[T]{
			X: Gx,
			Y: Gy,
		},
	}, nil
}

type AffinePoint[T emulated.FieldParams] struct {
	X, Y emulated.Element[T]
}

func (c *Curve[T, S]) Neg(p AffinePoint[T]) AffinePoint[T] {
	return AffinePoint[T]{
		X: p.X,
		Y: c.baseApi.Neg(p.Y).(emulated.Element[T]),
	}
}

func (c *Curve[T, S]) AssertIsEqual(p, q AffinePoint[T]) {
	c.baseApi.AssertIsEqual(p.X, q.X)
	c.baseApi.AssertIsEqual(p.Y, q.Y)
}

func (c *Curve[T, S]) AssertIsOnCurve(p AffinePoint[T]) {
	xx := c.baseApi.Mul(p.X, p.X)
	yy := c.baseApi.Mul(p.Y, p.Y)
	axx := c.baseApi.Mul(xx, c.a)
	lhs := c.baseApi.Add(axx, yy)

	dxx := c.baseApi.Mul(xx, c.d)
	dxxyy := c.baseApi.Mul(dxx, yy)
	rhs := c.baseApi.Add(dxxyy, 1)

	c.baseApi.AssertIsEqual(lhs, rhs)
}

func (c *Curve[T, S]) AssertIsZero(p AffinePoint[T]) {
	c.baseApi.AssertIsEqual(p.X, 0)
	c.baseApi.AssertIsEqual(p.Y, 1)
}

func (c *Curve[T, S]) Add(q, r AffinePoint[T]) AffinePoint[T] {
	// u = (x1 + y1) * (x2 + y2)
	u1 := c.baseApi.Mul(q.X, c.a)
	u1 = c.baseApi.Sub(q.Y, u1)
	u2 := c.baseApi.Add(r.X, r.Y)
	u := c.baseApi.Mul(u1, u2)

	// v0 = x1 * y2
	v0 := c.baseApi.Mul(r.Y, q.X)

	// v1 = x2 * y1
	v1 := c.baseApi.Mul(r.X, q.Y)

	// v2 = d * v0 * v1
	v2 := c.baseApi.Mul(c.d, v0, v1)

	var px, py frontend.Variable

	// x = (v0 + v1) / (1 + v2)
	px = c.baseApi.Add(v0, v1)
	px = c.baseApi.DivUnchecked(px, c.baseApi.Add(1, v2))

	// y = (u + a * v0 - v1) / (1 - v2)
	py = c.baseApi.Mul(c.a, v0)
	py = c.baseApi.Sub(py, v1)
	py = c.baseApi.Add(py, u)
	py = c.baseApi.DivUnchecked(py, c.baseApi.Sub(1, v2))

	return AffinePoint[T]{
		X: px.(emulated.Element[T]),
		Y: py.(emulated.Element[T]),
	}
}

func (c *Curve[T, S]) Double(p AffinePoint[T]) AffinePoint[T] {
	u := c.baseApi.Mul(p.X, p.Y)
	v := c.baseApi.Mul(p.X, p.X)
	w := c.baseApi.Mul(p.Y, p.Y)

	n1 := c.baseApi.Mul(2, u)
	av := c.baseApi.Mul(v, c.a)
	n2 := c.baseApi.Sub(w, av)
	d1 := c.baseApi.Add(w, av)
	d2 := c.baseApi.Sub(2, d1)

	px := c.baseApi.DivUnchecked(n1, d1)
	py := c.baseApi.DivUnchecked(n2, d2)

	return AffinePoint[T]{
		X: px.(emulated.Element[T]),
		Y: py.(emulated.Element[T]),
	}
}

func (c *Curve[T, S]) Select(b frontend.Variable, p, q AffinePoint[T]) AffinePoint[T] {
	x := c.baseApi.Select(b, p.X, q.X)
	y := c.baseApi.Select(b, p.Y, q.Y)
	return AffinePoint[T]{
		X: x.(emulated.Element[T]),
		Y: y.(emulated.Element[T]),
	}
}

func (c *Curve[T, S]) ScalarMul(p AffinePoint[T], s emulated.Element[S]) AffinePoint[T] {
	return c.ScalarMulBinary(p, c.scalarApi.ToBinary(s))
}

func (c *Curve[T, S]) ScalarMulBinary(p AffinePoint[T], sBits []frontend.Variable) AffinePoint[T] {
	res := AffinePoint[T]{
		X: emulated.NewElement[T](0),
		Y: emulated.NewElement[T](1),
	}
	acc := p

	for i := 0; i < len(sBits); i++ {
		tmp := c.Add(res, acc)
		res = c.Select(sBits[i], tmp, res)
		acc = c.Double(acc)
	}

	return res
}
