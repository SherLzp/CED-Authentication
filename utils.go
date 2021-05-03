package main

import (
	"hash"
)

func Hash(m []byte, hFunc func() hash.Hash) []byte {
	h := hFunc()
	h.Write(m)
	return h.Sum(nil)
}
