package types

func ReductionArityBits(
	arityBits uint64,
	finalPolyBits uint64,
	degreeBits uint64,
	rateBits uint64,
	capHeight uint64,
) []uint64 {
	returnArr := make([]uint64, 0)

	for degreeBits > finalPolyBits && degreeBits+rateBits-arityBits >= capHeight {
		returnArr = append(returnArr, arityBits)
		if degreeBits < arityBits {
			panic("degreeBits < arityBits")
		}
		degreeBits -= arityBits
	}

	return returnArr
}
