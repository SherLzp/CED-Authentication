package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestGenIdentity(t *testing.T) {
	mk, _ := GenMasterKey()
	uk, _ := GenUserKey(mk)
	round := 100
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := sk.X.String() + sk.Y.String()
	dName := "Camera"
	dManu := "Huawei"
	for i := 0; i < 10; i++ {
		fmt.Println("Amount: ", round)
		fmt.Println("------------")
		for j := 0; j < 3; j++ {
			t1 := time.Now()
			for i := 0; i < round; i++ {
				GenBtcAddress(pk)
			}
			fmt.Println(time.Since(t1))
			t2 := time.Now()
			for i := 0; i < round; i++ {
				GenIdentity(i, dName, dManu, time.Now().Unix())
			}
			fmt.Println(time.Since(t2))
			t3 := time.Now()
			for i := 0; i < round; i++ {
				id, _ := GenIdentity(i, dName, dManu, time.Now().Unix())
				Sign(uk, &mk.MasterPubKey, []byte(id))
			}
			fmt.Println(time.Since(t3))
		}
		fmt.Println("------------")
		round += 100
	}
}

func TestHash(t *testing.T) {
	round := 5000
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := sk.X.String() + sk.Y.String()
	dName := "Camera"
	dManu := "Huawei"
	t1 := time.Now()
	for i := 0; i < round; i++ {
		GenBtcAddress(pk)
	}
	fmt.Println(time.Since(t1))
	t2 := time.Now()
	for i := 0; i < round; i++ {
		GenIdentity(i, dName, dManu, time.Now().Unix())
	}
	fmt.Println(time.Since(t2))
}
