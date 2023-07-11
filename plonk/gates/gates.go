package gates

import (
	"fmt"
	"regexp"

	"github.com/consensys/gnark/frontend"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
)

type Gate interface {
	Id() string
	EvalUnfiltered(
		api frontend.API,
		glApi gl.Chip,
		vars EvaluationVars,
	) []gl.QuadraticExtensionVariable
}

var gateRegexHandlers = map[*regexp.Regexp]func(parameters map[string]string) Gate{
	aritheticGateRegex:          deserializeArithmeticGate,
	aritheticExtensionGateRegex: deserializeExtensionArithmeticGate,
	baseSumGateRegex:            deserializeBaseSumGate,
	constantGateRegex:           deserializeConstantGate,
	cosetInterpolationGateRegex: deserializeCosetInterpolationGate,
	exponentiationGateRegex:     deserializeExponentiationGate,
	mulExtensionGateRegex:       deserializeMulExtensionGate,
	noopGateRegex:               deserializeNoopGate,
	poseidonGateRegex:           deserializePoseidonGate,
	poseidonMdsGateRegex:        deserializePoseidonMdsGate,
	publicInputGateRegex:        deserializePublicInputGate,
	randomAccessGateRegex:       deserializeRandomAccessGate,
	reducingExtensionGateRegex:  deserializeReducingExtensionGate,
	reducingGateRegex:           deserializeReducingGate,
}

func GateInstanceFromId(gateId string) Gate {
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
