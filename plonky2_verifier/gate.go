package plonky2_verifier

import (
	"fmt"
	. "gnark-plonky2-verifier/field"
	"regexp"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/field/goldilocks"
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

	if strings.HasPrefix(gateId, "MulExtensionGate") {
		// Has the format "MulExtensionGate { num_ops: 13 }"

		regEx := "MulExtensionGate { num_ops: (?P<numOps>[0-9]+) }"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid MulExtensionGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numOps, hasNumOps := matches["numOps"]
		if !hasNumOps {
			panic("Invalid MulExtensionGate ID")
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

	if strings.HasPrefix(gateId, "ReducingGate") {
		// Has the format "ReducingGate { num_coeffs: 33 }"

		regEx := "ReducingGate { num_coeffs: (?P<numCoeffs>[0-9]+) }"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid ReducingGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numCoeffs, hasNumCoeffs := matches["numCoeffs"]
		if !hasNumCoeffs {
			panic("Invalid ReducingGate ID")
		}

		return NewReducingGate(uint64(numCoeffs))
	}

	if strings.HasPrefix(gateId, "ExponentiationGate") {
		// Has the format "ExponentiationGate { num_power_bits: 67, _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"

		regEx := "ExponentiationGate { num_power_bits: (?P<numPowerBits>[0-9]+), _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=(?P<base>[0-9]+)>"
		r, err := regexp.Compile(regEx)
		if err != nil {
			panic("Invalid ExponentiationGate regular expression")
		}

		matches := getRegExMatches(r, gateId)
		numPowerBits, hasNumPowerBits := matches["numPowerBits"]
		if !hasNumPowerBits {
			panic("Invalid ExponentiationGate ID")
		}

		return NewExponentiationGate(uint64(numPowerBits))
	}

	// CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 18446744069414584577, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 18446744069415632897, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>
	if strings.HasPrefix(gateId, "CosetInterpolationGate") {
		// Has the format CosetInterpolationGate { subgroup_bits: 4, degree: 6, barycentric_weights: [17293822565076172801, 18374686475376656385, 18446744069413535745, 281474976645120, 17592186044416, 18446744069414584577, 18446744000695107601, 18446744065119617025, 1152921504338411520, 72057594037927936, 18446744069415632897, 18446462594437939201, 18446726477228539905, 18446744069414584065, 68719476720, 4294967296], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>

		/*
			regEx := "CosetInterpolationGate { subgroup_bits: (?P<subgroupBits>[0-9]+), degree: (?P<degree>[0-9]+), barycentric_weights: \\[(?P<barycentricWeights>[0-9, ]+)\\], _phantom: PhantomData<plonky2_field::goldilocks_field::GoldilocksField> }<D=2>"
			r, err := regexp.Compile(regEx)
			if err != nil {
				panic("Invalid CosetInterpolationGate regular expression")
			}

			matches := getRegExMatches(r, gateId)
			subgroupBits, hasSubgroupBits := matches["subgroupBits"]
			degree, hasDegree := matches["degree"]
			barycentricWeights, hasBarycentricWeights := matches["barycentricWeights"]
			if !hasSubgroupBits || !hasDegree || !hasBarycentricWeights {
				panic("Invalid CosetInterpolationGate ID")
			}*/

		return NewCosetInterpolationGate(
			4,
			6,
			[]goldilocks.Element{
				goldilocks.NewElement(17293822565076172801),
				goldilocks.NewElement(18374686475376656385),
				goldilocks.NewElement(18446744069413535745),
				goldilocks.NewElement(281474976645120),
				goldilocks.NewElement(17592186044416),
				goldilocks.NewElement(18446744069414584577),
				goldilocks.NewElement(18446744000695107601),
				goldilocks.NewElement(18446744065119617025),
				goldilocks.NewElement(1152921504338411520),
				goldilocks.NewElement(72057594037927936),
				goldilocks.NewElement(18446744069415632897),
				goldilocks.NewElement(18446462594437939201),
				goldilocks.NewElement(18446726477228539905),
				goldilocks.NewElement(18446744069414584065),
				goldilocks.NewElement(68719476720),
				goldilocks.NewElement(4294967296),
			},
		)

	}

	panic(fmt.Sprintf("Unknown gate ID %s", gateId))
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
