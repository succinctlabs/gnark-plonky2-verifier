package types

import (
	"testing"
)

func TestDeserializeCommonCircuitData(t *testing.T) {
	DeserializeCommonCircuitData("../testdata/decode_block/common_circuit_data.json")
}
