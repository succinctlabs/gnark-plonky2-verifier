package plonky2_verifier

import (
	. "gnark-plonky2-verifier/field"
	"regexp"
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

	if strings.HasPrefix(gateId, "BaseSumGate") {
		// Has the format "BaseSumGate { num_limbs: 32 } + Base: 2"

		regEx := "BaseSumGate { num_limbs: (?P<numLimbs>[0-9]+) } \\+ Base: (?P<base>[0-9]+)"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid BaseSumGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numLimbs, hasNumLimbs := matches["numLimbs"]
		base, hasBase := matches["base"]
		if !hasNumLimbs || !hasBase {
			panic("Invalid BaseSumGate ID")
		}

		return NewBaseSumGate(uint64(numLimbs), uint64(base))
	}

	if strings.HasPrefix(gateId, "RandomAccessGate") {
		// Has the format "RandomAccessGate { bits: 2, num_copies: 13, num_extra_constants: 2, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"

		regEx := "RandomAccessGate { bits: (?P<bits>[0-9]+), num_copies: (?P<numCopies>[0-9]+), num_extra_constants: (?P<numExtraConstants>[0-9]+), _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=(?P<base>[0-9]+)>"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid RandomAccessGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		bits, hasBits := matches["bits"]
		numCopies, hasNumCopies := matches["numCopies"]
		numExtraConstants, hasNumExtraConstants := matches["numExtraConstants"]
		if !hasBits || !hasNumCopies || !hasNumExtraConstants {
			panic("Invalid RandomAccessGate ID")
		}

		return NewRandomAccessGate(uint64(bits), uint64(numCopies), uint64(numExtraConstants))
	}

	if strings.HasPrefix(gateId, "ArithmeticExtension") {
		// Has the format "ArithmeticExtensionGate { num_ops: 10 }"

		regEx := "ArithmeticExtensionGate { num_ops: (?P<numOps>[0-9]+) }"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid ArithmeticExtensionGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numOps, hasNumOps := matches["numOps"]
		if !hasNumOps {
			panic("Invalid ArithmeticExtensionGate ID")
		}

		return NewArithmeticExtensionGate(uint64(numOps))
	}

	if strings.HasPrefix(gateId, "MultiplicationExtension") {
		// Has the format "ArithmeticExtensionGate { num_ops: 10 }"

		regEx := "MultiplicationExtension { num_ops: (?P<numOps>[0-9]+) }"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid MultiplicationExtension regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numOps, hasNumOps := matches["numOps"]
		if !hasNumOps {
			panic("Invalid MultiplicationExtension ID")
		}

		return NewMultiplicationExtensionGate(uint64(numOps))
	}

	if strings.HasPrefix(gateId, "ReducingExtensionGate") {
		// Has the format "ReducingExtensionGate { num_coeffs: 33 }"

		regEx := "ReducingExtensionGate { num_coeffs: (?P<numCoeffs>[0-9]+) }"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid ReducingExtensionGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numCoeffs, hasNumCoeffs := matches["numCoeffs"]
		if !hasNumCoeffs {
			panic("Invalid ReducingExtensionGate ID")
		}

		return NewReducingExtensionGate(uint64(numCoeffs))
	}

	return nil
	//panic(fmt.Sprintf("Unknown gate ID %s", gateId))
}

func getRegExMatches(r *regexp.Regexp, gateId string) map[string]int {
	matches := r.FindStringSubmatch(gateId)
	result := make(map[string]int)
	for i, name := range r.SubexpNames() {
		if i != 0 && name != "" {
			value, err := strconv.Atoi(matches[i])
			if err != nil {
				panic("Invalid field value for \"name\": " + err.Error())
			}
			result[name] = value
		}
	}

	return result
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
