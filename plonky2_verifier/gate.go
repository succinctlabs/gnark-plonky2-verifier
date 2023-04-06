package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	"strconv"
	"strings"
)

type gate interface {
	Id() string
	EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension
}

func GateInstanceFromId(gateId string) gate {
	if strings.HasPrefix(gateId, "ArithmeticGate") {
		numOpsRaw := strings.Split(gateId, ":")[1]
		numOpsRaw = strings.Split(numOpsRaw, "}")[0]
		numOpsRaw = strings.TrimSpace(numOpsRaw)
		numOps, err := strconv.Atoi(numOpsRaw)
		if err != nil {
			panic("Invalid gate ID for ArithmeticGate")
		}
		return NewArithmeticGate(uint64(numOps))
	}

	if strings.HasPrefix(gateId, "ConstantGate") {
		numConstsRaw := strings.Split(gateId, ":")[1]
		numConstsRaw = strings.Split(numConstsRaw, "}")[0]
		numConstsRaw = strings.TrimSpace(numConstsRaw)
		numConsts, err := strconv.Atoi(numConstsRaw)
		if err != nil {
			panic("Invalid gate ID")
		}
		return NewConstantGate(uint64(numConsts))
	}

	if gateId == "NoopGate" {
		return NewNoopGate()
	}

	if gateId == "PublicInputGate" {
		return NewPublicInputGate()
	}

	if strings.HasPrefix(gateId, "PoseidonGate") {
		return NewPoseidonGate()
	}

	panic(fmt.Sprintf("Unknown gate ID %s", gateId))
}

func (p *PlonkChip) computeFilter(
	row uint64,
	groupRange Range,
	s QuadraticExtension,
	manySelector bool,
) QuadraticExtension {
	product := p.qeAPI.ONE_QE
	for i := groupRange.start; i < groupRange.end; i++ {
		if i == uint64(row) {
			continue
		}

		product = p.qeAPI.MulExtension(product, p.qeAPI.SubExtension(p.qeAPI.FieldToQE(NewFieldElement(i)), s))
	}

	if manySelector {
		product = p.qeAPI.MulExtension(product, p.qeAPI.SubExtension(p.qeAPI.FieldToQE(NewFieldElement(UNUSED_SELECTOR)), s))
	}

	return product
}

func (p *PlonkChip) evalFiltered(
	g gate,
	vars EvaluationVars,
	row uint64,
	selectorIndex uint64,
	groupRange Range,
	numSelectors uint64,
) []QuadraticExtension {
	filter := p.computeFilter(row, groupRange, vars.localConstants[selectorIndex], numSelectors > 1)

	vars.RemovePrefix(numSelectors)

	unfiltered := g.EvalUnfiltered(p, vars)
	for i := range unfiltered {
		unfiltered[i] = p.qeAPI.MulExtension(unfiltered[i], filter)
	}
	return unfiltered
}
