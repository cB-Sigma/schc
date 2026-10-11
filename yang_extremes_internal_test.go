// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package schc

import (
	"math/rand"
	"os"
	"testing"
)

// Property: RFC 9363 JSON with numbers swapped for extremes (0, the
// uint8/16/32/64 limits, negatives, exponents) and stray characters is
// read without panics, and whatever is read can be written back.
func TestYANGExtremeNumbers(t *testing.T) {
	seed, err := os.ReadFile("testdata/openschc/schc.json")
	if err != nil {
		t.Fatal(err)
	}
	small := []byte(`{"ietf-schc:schc":{"rule":[{"rule-id-value":1,"rule-id-length":8,"rule-nature":"nature-no-compression"}]}}`)
	nums := []string{"0", "1", "7", "16", "31", "32", "33", "63", "64", "255", "256", "65535", "4294967295", "18446744073709551615", "-1", "1e30"}
	chars := []byte("0123456789-e.:\"[]{},")
	rng := rand.New(rand.NewSource(9363))
	n := 5000
	if testing.Short() {
		n = 2000
	}
	for i := 0; i < n; i++ {
		base := seed
		if i%2 == 0 {
			base = small
		}
		b := append([]byte(nil), base...)
		for k := rng.Intn(3) + 1; k > 0; k-- {
			var starts []int
			for j := 1; j < len(b); j++ {
				if b[j] >= '0' && b[j] <= '9' && (b[j-1] == ':' || b[j-1] == ' ') {
					starts = append(starts, j)
				}
			}
			if len(starts) == 0 {
				break
			}
			s := starts[rng.Intn(len(starts))]
			e := s
			for e < len(b) && b[e] >= '0' && b[e] <= '9' {
				e++
			}
			b = append(append(append([]byte(nil), b[:s]...), nums[rng.Intn(len(nums))]...), b[e:]...)
		}
		if rng.Intn(2) == 0 {
			b[rng.Intn(len(b))] = chars[rng.Intn(len(chars))]
		}
		rs, _, err := ParseYANGWith(b, YANGOptions{SkipBadRules: true, TileBits: 16})
		if err != nil {
			continue
		}
		if _, err := rs.MarshalYANG(); err != nil {
			t.Fatalf("read but cannot write (%v):\n%s", err, b)
		}
	}
}
