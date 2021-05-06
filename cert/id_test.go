package cert

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
	uk, _ := GenUserKey(mk,"Edge_A")
	round := 1000
	sk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk := sk.X.String() + sk.Y.String()
	dName := "Camera"
	dManu := "Huawei"
	for i := 0; i < 10; i++ {
		fmt.Println("Amount: ", round)
		fmt.Println("------------")
		var e1, e2, e3 int64
		for j := 0; j < 3; j++ {
			t1 := time.Now()
			for i := 0; i < round; i++ {
				GenBtcAddress(pk)
			}
			e1 += time.Since(t1).Nanoseconds()
			t2 := time.Now()
			for i := 0; i < round; i++ {
				GenIdentity(i, dName, dManu, time.Now().Unix())
			}
			e2 += time.Since(t2).Nanoseconds()
			t3 := time.Now()
			for i := 0; i < round; i++ {
				id, _ := GenIdentity(i, dName, dManu, time.Now().Unix())
				Sign(uk, mk.Mpk, []byte(id))
			}
			e3 += time.Since(t3).Nanoseconds()
		}
		fmt.Println("比特币地址生成耗时: ", float64(e1)/float64(10000000), " ms")
		fmt.Println("无签名标识生成耗时: ", float64(e2)/float64(10000000), " ms")
		fmt.Println("带签名标识生成耗时: ", float64(e3)/float64(10000000), " ms")
		fmt.Println("------------")
		round += 1000
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
