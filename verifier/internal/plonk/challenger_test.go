package plonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestChallengerCircuit struct {
	commonCircuitDataFilename string `gnark:"-"`

	CircuitDigest             frontend.Variable `gnark:",public"`
	PublicInputs              []field.F         `gnark:",public"`
	WiresCap                  []frontend.Variable
	PlonkZsPartialProductsCap []frontend.Variable
	QuotientPolysCap          []frontend.Variable
	FriOpenings               fri.FriOpenings
	CommitPhaseMerkleCaps     [][]frontend.Variable
	FinalPoly                 common.PolynomialCoeffs
	PowWitness                field.F
}

func (circuit *TestChallengerCircuit) Define(api frontend.API) error {
	commonCircuitData := utils.DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)

	config := commonCircuitData.Config
	numChallenges := config.NumChallenges
	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(api, fieldAPI)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	poseidonBN128Chip := poseidon.NewPoseidonBN128Chip(api, fieldAPI)
	challenger := NewChallengerChip(api, fieldAPI, poseidonChip, poseidonBN128Chip)

	challenger.ObserveBN128Hash(circuit.CircuitDigest)
	challenger.ObserveHash(poseidonChip.HashNoPad(circuit.PublicInputs))
	challenger.ObserveCap(circuit.WiresCap)
	plonkBetas := challenger.GetNChallenges(numChallenges)
	plonkGammas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(circuit.PlonkZsPartialProductsCap)
	plonkAlphas := challenger.GetNChallenges(numChallenges)

	challenger.ObserveCap(circuit.QuotientPolysCap)
	plonkZeta := challenger.GetExtensionChallenge()

	challenger.ObserveOpenings(circuit.FriOpenings)

	friChallenges := challenger.GetFriChallenges(
		circuit.CommitPhaseMerkleCaps,
		circuit.FinalPoly,
		circuit.PowWitness,
		commonCircuitData.DegreeBits,
		config.FriConfig,
	)

	expectedPlonkBetas := [2]field.F{
		field.NewFieldConstFromString("17615363392879944733"),
		field.NewFieldConstFromString("9422446877322953047"),
	}

	expectedPlonkGammas := [2]field.F{
		field.NewFieldConstFromString("15174493176564484303"),
		field.NewFieldConstFromString("6175150444166239851"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkBetas[i], expectedPlonkBetas[i])
		fieldAPI.AssertIsEqual(plonkGammas[i], expectedPlonkGammas[i])
	}

	expectedPlonkAlphas := [2]field.F{
		field.NewFieldConstFromString("9276470834414745550"),
		field.NewFieldConstFromString("5302812342351431915"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkAlphas[i], expectedPlonkAlphas[i])
	}

	expectedPlonkZeta := field.QuadraticExtension{
		field.NewFieldConstFromString("3892795992421241388"),
		field.NewFieldConstFromString("15786647757418200302"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkZeta[i], expectedPlonkZeta[i])
	}

	fieldAPI.AssertIsEqual(friChallenges.FriAlpha[0], field.NewFieldConst(885535811531859621))

	fieldAPI.AssertIsEqual(friChallenges.FriBetas[0][0], field.NewFieldConst(5231781384587895507))

	fieldAPI.AssertIsEqual(friChallenges.FriPowResponse, field.NewFieldConst(70715523064019))

	fieldAPI.AssertIsEqual(friChallenges.FriQueryIndices[0], field.NewFieldConst(11890500485816111017))

	return nil
}

func StringToBN128Hash(hashStr string) poseidon.PoseidonBN128HashOut {
	hashBigInt, ok := new(big.Int).SetString(hashStr, 10)
	if !(ok) {
		panic("Invalid hash: " + hashStr)
	}

	hashVar := frontend.Variable(*hashBigInt)
	return poseidon.PoseidonBN128HashOut(hashVar)
}

func TestChallengerWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		proofWithPis := utils.DeserializeProofWithPublicInputs("../../data/decode_block/proof_with_public_inputs.json")
		verifierData := utils.DeserializeVerifierOnlyCircuitData("../../data/decode_block/verifier_only_circuit_data.json")

		circuit := TestChallengerCircuit{
			commonCircuitDataFilename: "../../data/decode_block/common_circuit_data.json",

			CircuitDigest:             verifierData.CircuitDigest,
			PublicInputs:              proofWithPis.PublicInputs,
			WiresCap:                  proofWithPis.Proof.WiresCap,
			PlonkZsPartialProductsCap: proofWithPis.Proof.PlonkZsPartialProductsCap,
			QuotientPolysCap:          proofWithPis.Proof.QuotientPolysCap,
			FriOpenings:               fri.ToFriOpenings(proofWithPis.Proof.Openings),
			CommitPhaseMerkleCaps:     proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
			FinalPoly:                 proofWithPis.Proof.OpeningProof.FinalPoly,
			PowWitness:                proofWithPis.Proof.OpeningProof.PowWitness,
		}
		witness := TestChallengerCircuit{
			CircuitDigest:             verifierData.CircuitDigest,
			PublicInputs:              proofWithPis.PublicInputs,
			WiresCap:                  proofWithPis.Proof.WiresCap,
			PlonkZsPartialProductsCap: proofWithPis.Proof.PlonkZsPartialProductsCap,
			QuotientPolysCap:          proofWithPis.Proof.QuotientPolysCap,
			FriOpenings:               fri.ToFriOpenings(proofWithPis.Proof.Openings),
			CommitPhaseMerkleCaps:     proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
			FinalPoly:                 proofWithPis.Proof.OpeningProof.FinalPoly,
			PowWitness:                proofWithPis.Proof.OpeningProof.PowWitness,
		}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}

func TestChallengerProver(t *testing.T) {
	proofWithPis := utils.DeserializeProofWithPublicInputs("../../data/decode_block/proof_with_public_inputs.json")
	verifierData := utils.DeserializeVerifierOnlyCircuitData("../../data/decode_block/verifier_only_circuit_data.json")

	circuit := TestChallengerCircuit{
		commonCircuitDataFilename: "../../data/decode_block/common_circuit_data.json",

		CircuitDigest:             verifierData.CircuitDigest,
		PublicInputs:              proofWithPis.PublicInputs,
		WiresCap:                  proofWithPis.Proof.WiresCap,
		PlonkZsPartialProductsCap: proofWithPis.Proof.PlonkZsPartialProductsCap,
		QuotientPolysCap:          proofWithPis.Proof.QuotientPolysCap,
		FriOpenings:               fri.ToFriOpenings(proofWithPis.Proof.Openings),
		CommitPhaseMerkleCaps:     proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
		FinalPoly:                 proofWithPis.Proof.OpeningProof.FinalPoly,
		PowWitness:                proofWithPis.Proof.OpeningProof.PowWitness,
	}

	proofWithPis = utils.DeserializeProofWithPublicInputs("../../data/decode_block/proof_with_public_inputs.json")
	verifierData = utils.DeserializeVerifierOnlyCircuitData("../../data/decode_block/verifier_only_circuit_data.json")

	assignment := TestChallengerCircuit{
		commonCircuitDataFilename: "../../data/decode_block/common_circuit_data.json",

		CircuitDigest:             verifierData.CircuitDigest,
		PublicInputs:              proofWithPis.PublicInputs,
		WiresCap:                  proofWithPis.Proof.WiresCap,
		PlonkZsPartialProductsCap: proofWithPis.Proof.PlonkZsPartialProductsCap,
		QuotientPolysCap:          proofWithPis.Proof.QuotientPolysCap,
		FriOpenings:               fri.ToFriOpenings(proofWithPis.Proof.Openings),
		CommitPhaseMerkleCaps:     proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
		FinalPoly:                 proofWithPis.Proof.OpeningProof.FinalPoly,
		PowWitness:                proofWithPis.Proof.OpeningProof.PowWitness,
	}

	r1cs, err := frontend.Compile(field.TEST_CURVE.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	println("num constraints is ", r1cs.GetNbConstraints())

	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &assignment, field.TEST_CURVE.ScalarField())
	assert.NoError(err)

	witness, err := frontend.NewWitness(&assignment, field.TEST_CURVE.ScalarField())
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
