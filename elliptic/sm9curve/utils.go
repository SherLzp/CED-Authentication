package sm9curve

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

func G1ToStr(p *G1) string {
	return hex.EncodeToString(p.Marshal())
}

func StrToG1(pStr string) *G1 {
	pBytes, _ := hex.DecodeString(pStr)
	p := new(G1)
	p.Unmarshal(pBytes)
	return p
}

func G2ToStr(p *G2) string {
	return hex.EncodeToString(p.Marshal())
}

func StrToG2(pStr string) *G2 {
	pBytes, _ := hex.DecodeString(pStr)
	p := new(G2)
	p.Unmarshal(pBytes)
	return p
}

func RandomValue() *big.Int {
	r, _ := rand.Int(rand.Reader, Order)
	return r
}
