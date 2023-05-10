package plonky2_verifier

const UNUSED_SELECTOR = uint64(^uint32(0)) // max uint32

type Range struct {
	start uint64
	end   uint64
}

type SelectorsInfo struct {
	selectorIndices []uint64
	groups          []Range
}

func (s *SelectorsInfo) NumSelectors() uint64 {
	return uint64(len(s.groups))
}
