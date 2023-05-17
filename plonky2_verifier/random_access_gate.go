package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
)

type RandomAccessGate struct {
	bits              uint64
	numCopies         uint64
	numExtraConstants uint64
}

func NewRandomAccessGate(bits uint64, numCopies uint64, numExtraConstants uint64) *RandomAccessGate {
	return &RandomAccessGate{
		bits:              bits,
		numCopies:         numCopies,
		numExtraConstants: numExtraConstants,
	}
}

func (g *RandomAccessGate) Id() string {
	return fmt.Sprintf("RandomAccessGate { bits: %d, num_copies: %d, num_extra_constants: %d }", g.bits, g.numCopies, g.numExtraConstants)
}

func (g *RandomAccessGate) vecSize() uint64 {
	return 1 << g.bits
}

func (g *RandomAccessGate) WireAccessIndex(copy uint64) uint64 {
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireAccessIndex called with copy >= num_copies")
	}
	return (2 + g.vecSize()) * copy
}

func (g *RandomAccessGate) WireClaimedElement(copy uint64) uint64 {
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireClaimedElement called with copy >= num_copies")
	}

	return (2+g.vecSize())*copy + 1
}

func (g *RandomAccessGate) WireListItem(i uint64, copy uint64) uint64 {
	if i >= g.vecSize() {
		panic("RandomAccessGate.WireListItem called with i >= vec_size")
	}
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireListItem called with copy >= num_copies")
	}

	return (2+g.vecSize())*copy + 2 + i
}

func (g *RandomAccessGate) startExtraConstants() uint64 {
	return (2 + g.vecSize()) * g.numCopies
}

func (g *RandomAccessGate) wireExtraConstant(i uint64) uint64 {
	if i >= g.numExtraConstants {
		panic("RandomAccessGate.wireExtraConstant called with i >= num_extra_constants")
	}

	return g.startExtraConstants() + i
}

func (g *RandomAccessGate) NumRoutedWires() uint64 {
	return g.startExtraConstants() + g.numExtraConstants
}

func (g *RandomAccessGate) WireBit(i uint64, copy uint64) uint64 {
	if i >= g.bits {
		panic("RandomAccessGate.WireBit called with i >= bits")
	}
	if copy >= g.numCopies {
		panic("RandomAccessGate.WireBit called with copy >= num_copies")
	}

	return g.NumRoutedWires() + copy*g.bits + i
}

func (g *RandomAccessGate) EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension {
	two := QuadraticExtension{NewFieldElement(2), NewFieldElement(0)}
	constraints := []QuadraticExtension{}

	for copy := uint64(0); copy < g.numCopies; copy++ {
		accessIndex := vars.localWires[g.WireAccessIndex(copy)]
		listItems := []QuadraticExtension{}
		for i := uint64(0); i < g.vecSize(); i++ {
			listItems = append(listItems, vars.localWires[g.WireListItem(i, copy)])
		}
		claimedElement := vars.localWires[g.WireClaimedElement(copy)]
		bits := []QuadraticExtension{}
		for i := uint64(0); i < g.bits; i++ {
			bits = append(bits, vars.localWires[g.WireBit(i, copy)])
		}

		// Assert that each bit wire value is indeed boolean.
		for _, b := range bits {
			bSquared := p.qeAPI.MulExtension(b, b)
			constraints = append(constraints, p.qeAPI.SubExtension(bSquared, b))
		}

		// Assert that the binary decomposition was correct.
		reconstructedIndex := p.qeAPI.ReduceWithPowers(bits, two)
		constraints = append(constraints, p.qeAPI.SubExtension(reconstructedIndex, accessIndex))

		for _, b := range bits {
			listItemsTmp := []QuadraticExtension{}
			for i := 0; i < len(listItems); i += 2 {
				x := listItems[i]
				y := listItems[i+1]

				// This is computing `if b { x } else { y }`
				// i.e. `bx - (by-y)`.
				mul1 := p.qeAPI.MulExtension(b, x)
				sub1 := p.qeAPI.SubExtension(mul1, x)

				mul2 := p.qeAPI.MulExtension(b, y)
				sub2 := p.qeAPI.SubExtension(mul2, sub1)

				listItemsTmp = append(listItemsTmp, sub2)
			}
			listItems = listItemsTmp
		}

		if len(listItems) != 1 {
			panic("listItems(len) != 1")
		}

		constraints = append(constraints, p.qeAPI.SubExtension(listItems[0], claimedElement))
	}

	for i := uint64(0); i < g.numExtraConstants; i++ {
		constraints = append(constraints, p.qeAPI.SubExtension(vars.localConstants[i], vars.localWires[g.wireExtraConstant(i)]))
	}

	return constraints
}
