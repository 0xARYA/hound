package houndTLSH

func modularDistance(x, y byte, R int) int {
	var dl, dr int

	if y > x {
		dl = int(y) - int(x)
		dr = int(x) + R - int(y)
	} else {
		dl = int(x) - int(y)
		dr = int(y) + R - int(x)
	}

	if dl > dr {
		return dr
	}

	return dl
}

func digestDistance(x [codeSize]byte, y [codeSize]byte) (diff int) {
	for i := 0; i < codeSize; i++ {
		diff += bitPairsDiffTable[x[i]][y[i]]
	}
	return
}

func totalDistance(a, b *TLSH, lenDiff bool) (diff int) {
	if lenDiff {
		lDiff := modularDistance(a.lValue, b.lValue, 256)

		if lDiff == 0 {
			diff = 0
		} else if lDiff == 1 {
			diff = 1
		} else {
			diff += lDiff * 12
		}
	}

	q1Diff := modularDistance(a.q1Ratio, b.q1Ratio, 16)
	if q1Diff <= 1 {
		diff += q1Diff
	} else {
		diff += (q1Diff - 1) * 12
	}

	q2Diff := modularDistance(a.q2Ratio, b.q2Ratio, 16)
	if q2Diff <= 1 {
		diff += q2Diff
	} else {
		diff += (q2Diff - 1) * 12
	}

	// currently we only support 1 byte checksum
	if a.checksum != b.checksum {
		diff++
	}

	diff += digestDistance(a.code, b.code)
	return diff
}
