package plonk

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/field"
	"github.com/succinctlabs/gnark-plonky2-verifier/poseidon"
)

type TestChallengerCircuit struct {
	PublicInputs              []field.F
	CircuitDigest             poseidon.PoseidonBN128HashOut
	WiresCap                  [16]poseidon.PoseidonBN128HashOut
	PlonkZsPartialProductsCap [16]poseidon.PoseidonBN128HashOut
	QuotientPolysCap          [16]poseidon.PoseidonBN128HashOut
}

func (circuit *TestChallengerCircuit) Define(api frontend.API) error {
	fieldAPI := field.NewFieldAPI(api)
	degreeBits := 3
	qeAPI := field.NewQuadraticExtensionAPI(api, fieldAPI, uint64(degreeBits))
	poseidonChip := poseidon.NewPoseidonChip(api, fieldAPI, qeAPI)
	poseidonBN128Chip := poseidon.NewPoseidonBN128Chip(api, fieldAPI)
	challengerChip := NewChallengerChip(api, fieldAPI, poseidonChip, poseidonBN128Chip)

	challengerChip.ObserveBN128Hash(circuit.CircuitDigest)
	publicInputHash := poseidonChip.HashNoPad(circuit.PublicInputs[:])
	challengerChip.ObserveHash(publicInputHash)
	challengerChip.ObserveCap(circuit.WiresCap[:])

	numChallenges := uint64(2)
	plonkBetas := challengerChip.GetNChallenges(numChallenges)
	plonkGammas := challengerChip.GetNChallenges(numChallenges)

	expectedPublicInputHash := [4]field.F{
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
		field.NewFieldConstFromString("0"),
	}

	for i := 0; i < 4; i++ {
		fieldAPI.AssertIsEqual(publicInputHash[i], expectedPublicInputHash[i])
	}

	expectedPlonkBetas := [2]field.F{
		field.NewFieldConstFromString("809252424062446818"),
		field.NewFieldConstFromString("7397814711529672408"),
	}

	expectedPlonkGammas := [2]field.F{
		field.NewFieldConstFromString("13664745396605828986"),
		field.NewFieldConstFromString("6326995011410399325"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkBetas[i], expectedPlonkBetas[i])
		fieldAPI.AssertIsEqual(plonkGammas[i], expectedPlonkGammas[i])
	}

	challengerChip.ObserveCap(circuit.PlonkZsPartialProductsCap[:])
	plonkAlphas := challengerChip.GetNChallenges(numChallenges)

	expectedPlonkAlphas := [2]field.F{
		field.NewFieldConstFromString("7047735366822651495"),
		field.NewFieldConstFromString("17475415137365152178"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkAlphas[i], expectedPlonkAlphas[i])
	}

	challengerChip.ObserveCap(circuit.QuotientPolysCap[:])
	plonkZeta := challengerChip.GetExtensionChallenge()

	expectedPlonkZeta := field.QuadraticExtension{
		field.NewFieldConstFromString("13764317411448234631"),
		field.NewFieldConstFromString("1167233795392151493"),
	}

	for i := 0; i < 2; i++ {
		fieldAPI.AssertIsEqual(plonkZeta[i], expectedPlonkZeta[i])
	}

	return nil
}

func hexStringToBN128Hash(hashHexStr string) poseidon.PoseidonBN128HashOut {
	hashBigInt, ok := new(big.Int).SetString(hashHexStr, 16)
	if !(ok) {
		panic("Invalid hash: " + hashHexStr)
	}

	println("hashBigInt is ", hashBigInt.String())
	hashVar := frontend.Variable(*hashBigInt)
	return poseidon.PoseidonBN128HashOut(hashVar)
}

func TestChallengerWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(
		publicInputs []field.F,
		circuitDigest poseidon.PoseidonBN128HashOut,
		wiresCap [16]poseidon.PoseidonBN128HashOut,
		plonkZsPartialProductsCap [16]poseidon.PoseidonBN128HashOut,
		quotientPolysCap [16]poseidon.PoseidonBN128HashOut,
	) {
		circuit := TestChallengerCircuit{
			PublicInputs:              publicInputs,
			CircuitDigest:             circuitDigest,
			WiresCap:                  wiresCap,
			PlonkZsPartialProductsCap: plonkZsPartialProductsCap,
			QuotientPolysCap:          quotientPolysCap,
		}
		witness := TestChallengerCircuit{
			PublicInputs:              publicInputs,
			CircuitDigest:             circuitDigest,
			WiresCap:                  wiresCap,
			PlonkZsPartialProductsCap: plonkZsPartialProductsCap,
			QuotientPolysCap:          quotientPolysCap,
		}
		err := test.IsSolved(&circuit, &witness, field.TEST_CURVE.ScalarField())
		assert.NoError(err)
	}

	publicInputs := []field.F{}

	circuitDigest := hexStringToBN128Hash("197f2a50ecbd8909ca03c144d328f43aab2568f74db4b535f0ddfd00338b0b6d")

	wiresCaps := [16]poseidon.PoseidonBN128HashOut{}
	wiresCaps[0] = hexStringToBN128Hash("0e689880d35b356f9d5adb56831182a8b42ce6997e5513ede80db8a3a883113d")
	wiresCaps[1] = hexStringToBN128Hash("2af7a57fd3c08fcfab5d974e24a4a8a8fd3c3ddb7fdd4222a9a2729bb2052501")
	wiresCaps[2] = hexStringToBN128Hash("0e9b8f5292ba96d6c08ae34b992dcb704f352a490dd005bf4bac012c9515fd6a")
	wiresCaps[3] = hexStringToBN128Hash("0622b3031ccbb15894a19fb2ea5561725704a95f1f40be48882bf5cc076de5e9")
	wiresCaps[4] = hexStringToBN128Hash("2c807d20d902d1e3f2d8d7e42b8e41e53a4338d1de89bbcb431576784bd4f5f4")
	wiresCaps[5] = hexStringToBN128Hash("111a6f40ac135a44435055a3a69659a3978f39b8da19c036a6dc28d74decb735")
	wiresCaps[6] = hexStringToBN128Hash("149aeb16cea471928d008d39e0d94ddf89447517281558b3204f897dd3a07014")
	wiresCaps[7] = hexStringToBN128Hash("0485b4c6b22e3a3319a6dc7ae2557999b1bb6c71a2759346a3f06a0271ca054f")
	wiresCaps[8] = hexStringToBN128Hash("12a823b9948f9b1020c9b034cb21a96651aa5bbde7054b08b851bf4f8c719210")
	wiresCaps[9] = hexStringToBN128Hash("2d6fabcb1f11d438dcc8f9872468542722f3b359c29c4128ca52a58fe2e1bef3")
	wiresCaps[10] = hexStringToBN128Hash("2abc9d440ce5ab10ab5c76c8eea40ee963471b60e71dcfc398ce74105f76b95c")
	wiresCaps[11] = hexStringToBN128Hash("0c0f2a9f30cc7b04a308f3c51e6c4d748c937f7a1911b9a449c202a5cc3d30b1")
	wiresCaps[12] = hexStringToBN128Hash("1b0e9fdcaef2a6b3c9e6b3c3c0a57a9610c28be71fa9dccf87c8d2bda5050f7d")
	wiresCaps[13] = hexStringToBN128Hash("2576890fb64676e2befab00ba8d315ca98f2b09bfa7852becb3361110a023ab9")
	wiresCaps[14] = hexStringToBN128Hash("1596113640b8d643d8ec32b2e2556e09a2b7f9d0ed03e9b4f004317f266470a3")
	wiresCaps[15] = hexStringToBN128Hash("2963b098124cbe3988bf3146a707c13d860765014cb7cb90d4c550540a1f65de")

	plonkZsPartialProductsCaps := [16]poseidon.PoseidonBN128HashOut{}
	plonkZsPartialProductsCaps[0] = hexStringToBN128Hash("0110b6ee5f9f6dd2cf85e622932cc9e2b294543c06aff8f39fefd4979cdb39c8")
	plonkZsPartialProductsCaps[1] = hexStringToBN128Hash("0c8b5890de655d31cc5f9fa410576351d0ac52b5dd53aacaaf21dcfcd5b5e6ec")
	plonkZsPartialProductsCaps[2] = hexStringToBN128Hash("1bbeabb166e95c348073c0e42e7f52ccd3fcfc32c60f2ed9fa22029255c4babb")
	plonkZsPartialProductsCaps[3] = hexStringToBN128Hash("1c5b784d9f44eb944fc4655dedb3c985703a447210bc2e1443ff38961adebcd6")
	plonkZsPartialProductsCaps[4] = hexStringToBN128Hash("120aa34fdf54512db9b9d2958ed63f3657ecc523bfb75267f4892d0ef6b93628")
	plonkZsPartialProductsCaps[5] = hexStringToBN128Hash("2c020c74b4a037c22dcbf27432a56fb8de986e933f86211bb4af8451622cc7d3")
	plonkZsPartialProductsCaps[6] = hexStringToBN128Hash("0f25f5c4978e0e75e4ad373154eb129bb2548b32429b397aea3d164e88f4d831")
	plonkZsPartialProductsCaps[7] = hexStringToBN128Hash("1ba85f4aaf468ac1b7c023a1ee7cd764b839879cc48221230d461b66ee43d60b")
	plonkZsPartialProductsCaps[8] = hexStringToBN128Hash("2a2adac69871e3704357a5d493338d45ca143bf27726191a81ef1c8b17404c11")
	plonkZsPartialProductsCaps[9] = hexStringToBN128Hash("196096a3abe31a883fe40f296f07ee4bb3248fc4556c21f74dcf48d9b4e637ff")
	plonkZsPartialProductsCaps[10] = hexStringToBN128Hash("0d22cb53a410ab0518d5fba620646766440551afb78c7624169f3522772db700")
	plonkZsPartialProductsCaps[11] = hexStringToBN128Hash("1eb4a2ee13f9f2965edb0bef25c851978a5a9a3aab26725589cd84822eb41ae6")
	plonkZsPartialProductsCaps[12] = hexStringToBN128Hash("01e3f850dc3dddc8976c76385ca54ee3158d58871b6a855bd514041e28bb7837")
	plonkZsPartialProductsCaps[13] = hexStringToBN128Hash("1b75a0baaeeda519bc414f48a808bf265e9af411991653f4e523c2ffd021e88a")
	plonkZsPartialProductsCaps[14] = hexStringToBN128Hash("0a994c8ae2db5d794898db4db1d8ce47bfae19389d4b454934ca52c6ceaad5bd")
	plonkZsPartialProductsCaps[15] = hexStringToBN128Hash("222f190ad8dc2ab6d6e35dc24b8f6e37816f1c612a70b00bd71629295e9a9f14")

	quotientPolysCaps := [16]poseidon.PoseidonBN128HashOut{}
	quotientPolysCaps[0] = hexStringToBN128Hash("26755c7d6b392fc3e4cd66f07f8ae67d034a0d2d38061368e0ba1e6324e57868")
	quotientPolysCaps[1] = hexStringToBN128Hash("298ee3376ae25fa53123e6d85d9956f2268270941d8e489c8995073dd6fe5e5a")
	quotientPolysCaps[2] = hexStringToBN128Hash("1135072daa3bd243cc02e796edcd12ba139389cd86703519b0e9aef590b76975")
	quotientPolysCaps[3] = hexStringToBN128Hash("1023a198b7cc0ca68c577be73fca042a88b36a792e26af67274975b708e2203b")
	quotientPolysCaps[4] = hexStringToBN128Hash("21e475225d588d1e81f4289fbbb3aaa364a4b3291314dc0032044b2258c261bc")
	quotientPolysCaps[5] = hexStringToBN128Hash("2be2f3f25bc8edae98ee680513442cc11ab03d4563f23f3663d3f728ecd497c4")
	quotientPolysCaps[6] = hexStringToBN128Hash("1d4bcac9b9cde1972809157cd1e341160e835bb01b6365c112c15ce69bc75289")
	quotientPolysCaps[7] = hexStringToBN128Hash("0918a2c60afdbcf07e37633794351ee2bb57f4a5376c0fa495952e7ee1fa753a")
	quotientPolysCaps[8] = hexStringToBN128Hash("1d2d5399b5cce8bf3c4bf56cfc1af05b142bbb94e457a99ae43e78c917824f84")
	quotientPolysCaps[9] = hexStringToBN128Hash("0efed09ab9c86bcfb5744ed29136c47482f58bd838a4a93b65f00aa6189d1986")
	quotientPolysCaps[10] = hexStringToBN128Hash("00fdb648d88876de8e0ed48d060a3ac8d778890c144e6ce8cf8b7b83b40c0703")
	quotientPolysCaps[11] = hexStringToBN128Hash("267dd6ec5c70f0f0949f5355099a78412e4ee2d2a1fe63f334c758988a2fe771")
	quotientPolysCaps[12] = hexStringToBN128Hash("1d82ed080a8108e5db601b8e8688fddca7ecbc61a76aacc100d167a1305033fd")
	quotientPolysCaps[13] = hexStringToBN128Hash("2d74e7e086f04f4f3abe8f04086516201520d699a579a0d29403d1d9dfeaa619")
	quotientPolysCaps[14] = hexStringToBN128Hash("1fd72ab2ae36d7cf6461e46b890f49134f43fca96f237d9aed70401e5a4542a8")
	quotientPolysCaps[15] = hexStringToBN128Hash("2e081f059297cb460dc8f8518ae8fda429d1d68737990828f20bc9e54a0ba5dc")

	testCase(publicInputs, circuitDigest, wiresCaps, plonkZsPartialProductsCaps, quotientPolysCaps)
}
