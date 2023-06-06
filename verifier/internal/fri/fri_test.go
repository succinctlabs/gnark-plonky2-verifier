package fri_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/common"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/fri"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/internal/plonk"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier/utils"
)

type TestFriCircuit struct {
	proofWithPIsFilename            string `gnark:"-"`
	commonCircuitDataFilename       string `gnark:"-"`
	verifierOnlyCircuitDataFilename string `gnark:"-"`
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	proofWithPis := utils.DeserializeProofWithPublicInputs(circuit.proofWithPIsFilename)
	commonCircuitData := utils.DeserializeCommonCircuitData(circuit.commonCircuitDataFilename)
	verifierOnlyCircuitData := utils.DeserializeVerifierOnlyCircuitData(circuit.verifierOnlyCircuitDataFilename)

	fieldAPI := field.NewFieldAPI(api)
	qeAPI := field.NewQuadraticExtensionAPI(api, fieldAPI, commonCircuitData.DegreeBits)
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	poseidonBN128Chip := poseidon.NewPoseidonBN128Chip(api, fieldAPI)
	friChip := fri.NewFriChip(api, fieldAPI, qeAPI, poseidonBN128Chip, &commonCircuitData.FriParams)
	challengerChip := plonk.NewChallengerChip(api, fieldAPI, poseidonChip, poseidonBN128Chip)

	challengerChip.ObserveBN128Hash(verifierOnlyCircuitData.CircuitDigest)
	challengerChip.ObserveHash(poseidonChip.HashNoPad(proofWithPis.PublicInputs))
	challengerChip.ObserveCap(proofWithPis.Proof.WiresCap)
	plonkBetas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk betas
	fieldAPI.AssertIsEqual(plonkBetas[0], field.NewFieldConst(17615363392879944733))
	plonkGammas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk gammas
	fieldAPI.AssertIsEqual(plonkGammas[0], field.NewFieldConst(15174493176564484303))

	challengerChip.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
	plonkAlphas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk alphas
	fieldAPI.AssertIsEqual(plonkAlphas[0], field.NewFieldConst(9276470834414745550))

	challengerChip.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
	plonkZeta := challengerChip.GetExtensionChallenge()
	fieldAPI.AssertIsEqual(plonkZeta[0], field.NewFieldConst(3892795992421241388))

	friChallenges := challengerChip.GetFriChallenges(
		proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
		proofWithPis.Proof.OpeningProof.FinalPoly,
		proofWithPis.Proof.OpeningProof.PowWitness,
		commonCircuitData.DegreeBits,
		commonCircuitData.Config.FriConfig,
	)

	initialMerkleCaps := []common.MerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	friChip.VerifyFriProof(
		fri.GetFriInstance(&commonCircuitData, qeAPI, plonkZeta, commonCircuitData.DegreeBits),
		fri.ToFriOpenings(proofWithPis.Proof.Openings),
		&friChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)

	return nil
}

func TestDummyFriProof(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		circuit := TestFriCircuit{
			proofWithPIsFilename:            "../../data/decode_block/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "../../data/decode_block//common_circuit_data.json",
			verifierOnlyCircuitDataFilename: "../../data/decode_block//verifier_only_circuit_data.json",
		}
		witness := TestFriCircuit{
			proofWithPIsFilename:            "../../data/dummy_2^14_gates/proof_with_public_inputs.json",
			commonCircuitDataFilename:       "../../data/dummy_2^14_gates/common_circuit_data.json",
			verifierOnlyCircuitDataFilename: ".../../data/dummy_2^14_gates/verifier_only_circuit_data.json",
		}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
