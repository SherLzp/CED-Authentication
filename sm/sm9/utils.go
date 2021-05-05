package sm9

import (
	"crypto/sha256"
	"hash"
)

func KDF(data []byte, keyByteLen int) []byte {
	groupNum := (keyByteLen*8 + (256*8-1)/(256*8))
	var hv []byte
	for ct := 1; ct <= groupNum; ct++ {
		var t []byte
		t = append(t, data...)
		t = append(t, byte(ct>>24&255))
		t = append(t, byte(ct>>16&255))
		t = append(t, byte(ct>>8&255))
		t = append(t, byte(ct&255))
		hv = append(hv, Hash(t, sha256.New)...)
	}
	return hv[:keyByteLen]
}

func MAC(key []byte, data []byte) []byte {
	var hv, t []byte
	t = append(t, data...)
	t = append(t, key...)
	hv = Hash(t, sha256.New)
	return hv
}

func Hash(m []byte, hFunc func() hash.Hash) []byte {
	h := hFunc()
	h.Write(m)
	return h.Sum(nil)
}

func XOR(a, b []byte) []byte {
	var length int
	if len(a) > len(b) {
		length = len(b)
	} else {
		length = len(a)
	}
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte((a[i] ^ b[i]) & 255)
	}
	return result
}
