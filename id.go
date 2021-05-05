package main

import (
	"ced-paper/CED-Authentication/sm/sm9"
	"crypto/sha256"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
	"strconv"
)

func GenIdentity(dNum int, dName string, dManu string, creteAt int64) (string, error) {
	var res []byte
	res = append(res, []byte(strconv.Itoa(dNum))...)
	res = append(res, []byte(dName)...)
	res = append(res, []byte(dManu)...)
	res = append(res, []byte(strconv.FormatInt(creteAt, 10))...)
	//fmt.Println("1:", res)
	hash1 := sm9.Hash(res, sha256.New)
	//fmt.Println("2:", hash1)
	res = append(res, hash1...)
	hash2 := sm9.Hash(res, sha256.New)
	//fmt.Println("3:", hash2)
	hash3 := sm9.Hash(hash2, ripemd160.New)
	//fmt.Println("4:", hash3)
	id := base58.Encode(hash3)
	//fmt.Println("5:", id)
	return id, nil
}

func GenBtcAddress(pk string) (string, error) {
	h1 := sm9.Hash([]byte(pk), sha256.New)
	pkHash := sm9.Hash(h1, ripemd160.New)
	var h2 []byte
	h2 = append(h2, []byte("0x00")...)
	h2 = append(h2, pkHash...)
	h3 := sm9.Hash(h2, sha256.New)
	h3 = sm9.Hash(h3, sha256.New)
	var h4 []byte
	h4 = append(h4, []byte("0x00")...)
	h4 = append(h4, pkHash...)
	h4 = append(h4, h3[:4]...)
	addr := base58.Encode(h4)
	return addr, nil
}
