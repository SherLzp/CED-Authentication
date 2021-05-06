// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm9

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func TestSign(t *testing.T) {
	mk, err := MasterKeyGen(rand.Reader)
	if err != nil {
		t.Errorf("mk gen failed:%s", err)
		return
	}

	var hid byte = 1

	var uid = []byte("Alice")

	uk, err := UserKeyGen(mk, uid, hid)
	if err != nil {
		t.Errorf("uk gen failed:%s", err)
		return
	}

	msg := []byte("message")

	sig, err := Sign(uk, mk.Mpk, msg)
	if err != nil {
		t.Errorf("sm9 sign failed:%s", err)
		return
	}

	if !Verify(sig, msg, uid, hid, mk.Mpk) {
		t.Error("sm9 sig is invalid")
		return
	}
}

func BenchmarkMasterKeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = MasterKeyGen(rand.Reader)
	}
}

func BenchmarkUserKeyGen(b *testing.B) {
	mk, _ := MasterKeyGen(rand.Reader)
	id := []byte("Alice")
	hid := 3
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = UserKeyGen(mk, id, byte(hid))
	}
}

func BenchmarkSign(b *testing.B) {
	mk, _ := MasterKeyGen(rand.Reader)
	id := []byte("Alice")
	hid := 3
	uk, _ := UserKeyGen(mk, id, byte(hid))

	var msg = []byte("message")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(uk, mk.Mpk, msg)
	}
}

func BenchmarkVerify(b *testing.B) {
	mk, _ := MasterKeyGen(rand.Reader)
	id := []byte("Alice")
	hid := 3
	uk, _ := UserKeyGen(mk, id, byte(hid))

	var msg = []byte("message")

	sig, _ := Sign(uk, mk.Mpk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Verify(sig, msg, id, byte(hid), mk.Mpk)
	}
}

func TestDecrypt(t *testing.T) {
	mk, _ := MasterKeyGen(rand.Reader)
	idA := []byte("A")
	hid := byte(1)
	uk, _ := UserKeyGen(mk, idA, hid)
	m := []byte("test")
	enc := Encrypt(mk.MEncPk, m, idA, hid)
	mPrime := Decrypt(enc, idA, uk.EncSk)
	fmt.Println(string(mPrime))
}
