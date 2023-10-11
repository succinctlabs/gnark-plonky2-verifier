package fri_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/challenger"
	"github.com/succinctlabs/gnark-plonky2-verifier/fri"
	gl "github.com/succinctlabs/gnark-plonky2-verifier/goldilocks"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
)

type TestFriCircuit struct {
	ProofWithPis            variables.ProofWithPublicInputs
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData
	CommonCircuitData       types.CommonCircuitData
}

func (circuit *TestFriCircuit) Define(api frontend.API) error {
	commonCircuitData := circuit.CommonCircuitData
	verifierOnlyCircuitData := circuit.VerifierOnlyCircuitData
	proofWithPis := circuit.ProofWithPis

	glApi := gl.New(api)
	poseidonChip := poseidon.NewGoldilocksChip(api)
	friChip := fri.NewChip(api, &commonCircuitData, &commonCircuitData.FriParams)
	challengerChip := challenger.NewChip(api)

	challengerChip.ObserveBN254Hash(verifierOnlyCircuitData.CircuitDigest)
	challengerChip.ObserveHash(poseidonChip.HashNoPad(proofWithPis.PublicInputs))
	challengerChip.ObserveCap(proofWithPis.Proof.WiresCap)
	plonkBetas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk betas
	glApi.AssertIsEqual(plonkBetas[0], gl.NewVariable("17615363392879944733"))
	plonkGammas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk gammas
	glApi.AssertIsEqual(plonkGammas[0], gl.NewVariable("15174493176564484303"))

	challengerChip.ObserveCap(proofWithPis.Proof.PlonkZsPartialProductsCap)
	plonkAlphas := challengerChip.GetNChallenges(commonCircuitData.Config.NumChallenges) // For plonk alphas
	glApi.AssertIsEqual(plonkAlphas[0], gl.NewVariable("9276470834414745550"))

	challengerChip.ObserveCap(proofWithPis.Proof.QuotientPolysCap)
	plonkZeta := challengerChip.GetExtensionChallenge()
	glApi.AssertIsEqual(plonkZeta[0], gl.NewVariable("3892795992421241388"))

	challengerChip.ObserveOpenings(friChip.ToOpenings(proofWithPis.Proof.Openings))

	friChallenges := challengerChip.GetFriChallenges(
		proofWithPis.Proof.OpeningProof.CommitPhaseMerkleCaps,
		proofWithPis.Proof.OpeningProof.FinalPoly,
		proofWithPis.Proof.OpeningProof.PowWitness,
		commonCircuitData.DegreeBits,
		commonCircuitData.Config.FriConfig,
	)

	api.AssertIsEqual(friChallenges.FriAlpha[0].Limb, 885535811531859621)

	api.AssertIsEqual(friChallenges.FriBetas[0][0].Limb, 5231781384587895507)

	api.AssertIsEqual(friChallenges.FriPowResponse.Limb, 70715523064019)

	// glApi.AssertIsEqual(friChallenges.FriQueryIndices[0], gl.NewVariableFromConst(11890500485816111017))
	var x uint64
	x = 11890500485816111017
	api.AssertIsEqual(friChallenges.FriQueryIndices[0].Limb, x)

	initialMerkleCaps := []variables.FriMerkleCap{
		verifierOnlyCircuitData.ConstantSigmasCap,
		proofWithPis.Proof.WiresCap,
		proofWithPis.Proof.PlonkZsPartialProductsCap,
		proofWithPis.Proof.QuotientPolysCap,
	}

	// Seems like there is a bug in the emulated field code.
	// Add ZERO to all of the fri challenges values to reduce them.
	plonkZeta[0] = glApi.Add(plonkZeta[0], gl.Zero())
	plonkZeta[1] = glApi.Add(plonkZeta[1], gl.Zero())

	friChallenges.FriAlpha[0] = glApi.Add(friChallenges.FriAlpha[0], gl.Zero())
	friChallenges.FriAlpha[1] = glApi.Add(friChallenges.FriAlpha[1], gl.Zero())

	for i := 0; i < len(friChallenges.FriBetas); i++ {
		friChallenges.FriBetas[i][0] = glApi.Add(friChallenges.FriBetas[i][0], gl.Zero())
		friChallenges.FriBetas[i][1] = glApi.Add(friChallenges.FriBetas[i][1], gl.Zero())
	}

	friChallenges.FriPowResponse = glApi.Add(friChallenges.FriPowResponse, gl.Zero())

	for i := 0; i < len(friChallenges.FriQueryIndices); i++ {
		friChallenges.FriQueryIndices[i] = glApi.Add(friChallenges.FriQueryIndices[i], gl.Zero())
	}

	friChip.VerifyFriProof(
		friChip.GetInstance(plonkZeta),
		friChip.ToOpenings(proofWithPis.Proof.Openings),
		&friChallenges,
		initialMerkleCaps,
		&proofWithPis.Proof.OpeningProof,
	)

	return nil
}

func TestDecodeBlockFriVerification(t *testing.T) {
	assert := test.NewAssert(t)

	proofWithPIsFilename := "../testdata/decode_block/proof_with_public_inputs.json"
	commonCircuitDataFilename := "../testdata/decode_block/common_circuit_data.json"
	verifierOnlyCircuitDataFilename := "../testdata/decode_block/verifier_only_circuit_data.json"

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(proofWithPIsFilename))
	commonCircuitData := types.ReadCommonCircuitData(commonCircuitDataFilename)
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(verifierOnlyCircuitDataFilename))

	testCase := func() {
		circuit := TestFriCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		witness := TestFriCircuit{
			proofWithPis,
			verifierOnlyCircuitData,
			commonCircuitData,
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err)
	}

	testCase()
}
