// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package v44_test

import (
	"bytes"
	"fmt"

	"github.com/cB-Sigma/schc/v44"
)

// Compress one packet with the annex B.1.2 default parameters and
// decompress it with the same parameters.
func ExampleCompress() {
	p := v44.DefaultParams()
	src := bytes.Repeat([]byte("0-0:96.1.0.255 meter "), 20)
	packed, err := v44.Compress(p, src)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(src), "->", len(packed) < len(src)/4)
	back, err := v44.Decompress(p, packed)
	fmt.Println(bytes.Equal(back, src), err)
	// Output:
	// 420 -> true
	// true <nil>
}
