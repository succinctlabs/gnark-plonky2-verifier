package goldilocks

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type GoldilocksElement = emulated.Element[emulated.Goldilocks]

func NewGoldilocksElement(x uint64) GoldilocksElement {
	return GoldilocksElement(emulated.NewElement[emulated.Goldilocks](x))
}

func NewGoldilocksAPI(api frontend.API) frontend.API {
	goldilocks, err := emulated.NewField[emulated.Goldilocks](api)
	if err != nil {
		panic(err)
	}
	return goldilocks
}
