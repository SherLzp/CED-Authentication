package sm9

import (
	"ced-paper/CED-Authentication/_const"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"math/big"
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

func BigIntToStr(p *big.Int) string {
	return hex.EncodeToString(p.Bytes())
}

func StrToBigInt(pStr string) *big.Int {
	pBytes, _ := hex.DecodeString(pStr)
	return new(big.Int).SetBytes(pBytes)
}

func EncodeEnc(enc *Sm9Enc) string {
	encBytes, _ := json.Marshal(enc)
	return hex.EncodeToString(encBytes)
}

func DecodeEnc(encStr string) *Sm9Enc {
	enc := new(Sm9Enc)
	encBytes, _ := hex.DecodeString(encStr)
	json.Unmarshal(encBytes, &enc)
	return enc
}

func Mk() *MasterKey {
	mkBytes, _ := hex.DecodeString(_const.MK)
	mk := new(MasterKey)
	json.Unmarshal(mkBytes, &mk)
	return mk
}

func Uk1() *UserKey {
	uk1Bytes, _ := hex.DecodeString(_const.UK1)
	uk := new(UserKey)
	json.Unmarshal(uk1Bytes, &uk)
	return uk
}

func Uk2() *UserKey {
	uk2Bytes, _ := hex.DecodeString(_const.UK2)
	uk := new(UserKey)
	json.Unmarshal(uk2Bytes, &uk)
	return uk
}
