package gates

const UNUSED_SELECTOR = uint64(^uint32(0)) // max uint32

// Range defines a range with a start and end value.
type Range struct {
	start uint64
	end   uint64
}

// SelectorsInfo stores information about selectors and their groups.
type SelectorsInfo struct {
	selectorIndices []uint64 // Indices of selectors.
	groups          []Range  // Ranges defining groups of selectors.
}

// NewSelectorsInfo creates a new SelectorsInfo instance.
// It validates that groupStarts and groupEnds have the same length.
func NewSelectorsInfo(selectorIndices []uint64, groupStarts []uint64, groupEnds []uint64) *SelectorsInfo {
	if len(groupStarts) != len(groupEnds) {
		panic("groupStarts and groupEnds must have the same length")
	}

	groups := []Range{}
	for i := range groupStarts {
		groups = append(groups, Range{
			start: groupStarts[i],
			end:   groupEnds[i],
		})
	}

	return &SelectorsInfo{
		selectorIndices: selectorIndices,
		groups:          groups,
	}
}

// NumSelectors returns the number of selector groups.
func (s *SelectorsInfo) NumSelectors() uint64 {
	return uint64(len(s.groups))
}
