package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	"regexp"
)

type gate interface {
	Id() string
	EvalUnfiltered(p *PlonkChip, vars EvaluationVars) []QuadraticExtension
}

var gateRegexHandlers = map[*regexp.Regexp]func(parameters map[string]string) gate{
	aritheticGateRegex:          deserializeArithmeticGate,
	aritheticExtensionGateRegex: deserializeExtensionArithmeticGate,
	baseSumGateRegex:            deserializeBaseSumGate,
	constantGateRegex:           deserializeConstantGate,
	cosetInterpolationGateRegex: deserializeCosetInterpolationGate,
	exponentiationGateRegex:     deserializeExponentiationGate,
	mulExtensionGateRegex:       deserializeMulExtensionGate,
	noopGateRegex:               deserializeNoopGate,
	poseidonGateRegex:           deserializePoseidonGate,
	publicInputGateRegex:        deserializePublicInputGate,
	randomAccessGateRegex:       deserializeRandomAccessGate,
	reducingExtensionGateRegex:  deserializeReducingExtensionGate,
	reducingGateRegex:           deserializeReducingGate,
}

func GateInstanceFromId(gateId string) gate {
	for regex, handler := range gateRegexHandlers {
		matches := regex.FindStringSubmatch(gateId)
		if matches != nil {
			parameters := make(map[string]string)
			for i, name := range regex.SubexpNames() {
				if i != 0 && name != "" {
					parameters[name] = matches[i]
				}
			}

			if matches != nil {
				return handler(parameters)
			}
		}
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
