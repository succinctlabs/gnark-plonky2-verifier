package plonky2_verifier

const UNUSED_SELECTOR = ^uint64(0) // max uint

type Range struct {
	start uint64
	end   uint64
}

type SelectorsInfo struct {
	selectorIndices []uint64
	groups          []Range
}

func (s *SelectorsInfo) NumSelectors() int {
	return len(s.groups)
}
