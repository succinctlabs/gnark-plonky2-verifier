package gates

import (
	"github.com/consensys/gnark/frontend"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
)

type EvaluateGatesChip struct {
	api   frontend.API
	qeAPI *field.QuadraticExtensionAPI

	gates              []Gate
	numGateConstraints uint64

	selectorsInfo SelectorsInfo
}

func NewEvaluateGatesChip(
	api frontend.API,
	qeAPI *field.QuadraticExtensionAPI,
	gates []Gate,
	numGateConstraints uint64,
	selectorsInfo SelectorsInfo,
) *EvaluateGatesChip {
	return &EvaluateGatesChip{
		api:   api,
		qeAPI: qeAPI,

		gates:              gates,
		numGateConstraints: numGateConstraints,

		selectorsInfo: selectorsInfo,
	}
}

func (g *EvaluateGatesChip) computeFilter(
	row uint64,
	groupRange Range,
	s field.QuadraticExtension,
	manySelector bool,
) field.QuadraticExtension {
	product := g.qeAPI.ONE_QE
	for i := groupRange.start; i < groupRange.end; i++ {
		if i == uint64(row) {
			continue
		}

		product = g.qeAPI.MulExtension(product, g.qeAPI.SubExtension(g.qeAPI.FieldToQE(*field.NewFieldConst(i)), s))
	}

	if manySelector {
		product = g.qeAPI.MulExtension(product, g.qeAPI.SubExtension(g.qeAPI.FieldToQE(*field.NewFieldConst(UNUSED_SELECTOR)), s))
	}

	return product
}

func (g *EvaluateGatesChip) evalFiltered(
	gate Gate,
	vars EvaluationVars,
	row uint64,
	selectorIndex uint64,
	groupRange Range,
	numSelectors uint64,
) []field.QuadraticExtension {
	filter := g.computeFilter(row, groupRange, vars.localConstants[selectorIndex], numSelectors > 1)

	vars.RemovePrefix(numSelectors)

	unfiltered := gate.EvalUnfiltered(g.api, g.qeAPI, vars)
	for i := range unfiltered {
		unfiltered[i] = g.qeAPI.MulExtension(unfiltered[i], filter)
	}
	return unfiltered
}

func (g *EvaluateGatesChip) EvaluateGateConstraints(vars EvaluationVars) []field.QuadraticExtension {
	constraints := make([]field.QuadraticExtension, g.numGateConstraints)
	for i := range constraints {
		constraints[i] = g.qeAPI.ZERO_QE
	}

	for i, gate := range g.gates {
		selectorIndex := g.selectorsInfo.selectorIndices[i]

		gateConstraints := g.evalFiltered(
			gate,
			vars,
			uint64(i),
			selectorIndex,
			g.selectorsInfo.groups[selectorIndex],
			g.selectorsInfo.NumSelectors(),
		)

		for i, constraint := range gateConstraints {
			if uint64(i) >= g.numGateConstraints {
				panic("num_constraints() gave too low of a number")
			}
			constraints[i] = g.qeAPI.AddExtension(constraints[i], constraint)
		}
	}

	return constraints
}
