// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm9

import (
	"ced-paper/CED-Authentication/elliptic/sm9curve"
	"crypto/rand"
	"encoding/binary"
	"github.com/pkg/errors"
	"github.com/xlcetc/cryptogm/sm/sm3"
	"io"
	"math"
	"math/big"
)

type hashMode int

const (
	H1 hashMode = iota
	H2
)

//SMHash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func SMHash(z []byte, n *big.Int, h hashMode) *big.Int {
	//counter
	ct := 1

	hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))

	var ha []byte
	for i := 0; i < int(math.Ceil(float64(hlen/256))); i++ {
		msg := append([]byte{byte(h)}, z...)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(ct))
		msg = append(msg, buf...)
		hai := sm3.SumSM3(msg)
		ct++
		if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
			ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
		} else {
			ha = append(ha, hai[:]...)
		}
	}

	bn := new(big.Int).SetBytes(ha)
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	bn.Mod(bn, nMinus1)
	bn.Add(bn, one)

	return bn
}

//generate rand numbers in [1,n-1].
func randFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
	one := big.NewInt(1)
	b := make([]byte, 256/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	nMinus1 := new(big.Int).Sub(n, one)
	k.Mod(k, nMinus1)
	return
}

//generate master key for KGC(Key Generate Center).
func MasterKeyGen(rand io.Reader) (mk *MasterKey, err error) {
	s1, err := randFieldElement(rand, sm9curve.Order)
	s2, err := randFieldElement(rand, sm9curve.Order)
	if err != nil {
		return nil, errors.Errorf("gen rand num err:%s1", err)
	}

	mk = new(MasterKey)
	mk.Msk = new(big.Int).Set(s1)
	mk.MEncSk = new(big.Int).Set(s2)

	mk.Mpk = new(sm9curve.G2).ScalarBaseMult(s1)
	mk.MEncPk = new(sm9curve.G1).ScalarBaseMult(s2)
	return mk, nil
}

//generate user's secret key.
func UserKeyGen(mk *MasterKey, id []byte, hid byte) (uk *UserKey, err error) {
	id = append(id, hid)
	n := sm9curve.Order
	t1 := SMHash(id, n, H1)
	h1 := new(big.Int).Add(t1, mk.Msk)
	h2 := new(big.Int).Add(t1, mk.MEncSk)

	//if t1 = 0, we need to regenerate the master key.
	if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
		return nil, errors.New("need to regen mk!")
	}

	h1.ModInverse(h1, n)
	h2.ModInverse(h2, n)

	//t2 = s*t1^-1
	t2 := new(big.Int).Mul(mk.Msk, h1)
	t2Prime := new(big.Int).Mul(mk.MEncSk, h2)

	uk = new(UserKey)
	uk.Sk = new(sm9curve.G1).ScalarBaseMult(t2)
	uk.EncSk = new(sm9curve.G2).ScalarBaseMult(t2Prime)
	return
}

//sm9 sign algorithm:
//A1:compute g = e(P1,Ppub);
//A2:choose random num r in [1,n-1];
//A3:compute w = g^r;
//A4:compute h = H2(M||w,n);
//A5:compute l = (r-h) mod n, if l = 0 goto A2;
//A6:compute S = l·sk.
func Sign(uk *UserKey, mpk *sm9curve.G2, msg []byte) (sig *Sm9Sig, err error) {
	sig = new(Sm9Sig)
	n := sm9curve.Order
	g := sm9curve.Pair(sm9curve.Gen1, mpk)

regen:
	r, err := randFieldElement(rand.Reader, n)
	if err != nil {
		return nil, errors.Errorf("gen rand num failed:%s", err)
	}

	w := new(sm9curve.GT).ScalarMult(g, r)

	wBytes := w.Marshal()

	msg = append(msg, wBytes...)

	h := SMHash(msg, n, H2)

	sig.H = new(big.Int).Set(h)

	l := new(big.Int).Sub(r, h)
	l.Mod(l, n)

	if l.BitLen() == 0 {
		goto regen
	}

	sig.S = new(sm9curve.G1).ScalarMult(uk.Sk, l)

	return
}

//sm9 verify algorithm(given sig (h',S'), message M' and user's id):
//B1:compute g = e(P1,Ppub);
//B2:compute t = g^h';
//B3:compute h1 = H1(id||hid,n);
//B4:compute P = h1·P2+Ppub;
//B5:compute u = e(S',P);
//B6:compute w' = u·t;
//B7:compute h2 = H2(M'||w',n), check if h2 = h'.
func Verify(sig *Sm9Sig, msg []byte, id []byte, hid byte, mpk *sm9curve.G2) bool {
	n := sm9curve.Order
	g := sm9curve.Pair(sm9curve.Gen1, mpk)

	t := new(sm9curve.GT).ScalarMult(g, sig.H)

	id = append(id, hid)

	h1 := SMHash(id, n, H1)

	P := new(sm9curve.G2).ScalarBaseMult(h1)

	P.Add(P, mpk)

	u := sm9curve.Pair(sig.S, P)

	w := new(sm9curve.GT).Add(u, t)

	wBytes := w.Marshal()

	msg = append(msg, wBytes...)

	h2 := SMHash(msg, n, H2)

	if h2.Cmp(sig.H) != 0 {
		return false
	}

	return true
}

func Encrypt(key *sm9curve.G1, m []byte, id []byte, hid byte) (*Sm9Enc) {
	cId := append(id, hid)
	n := sm9curve.Order
	t1 := SMHash(cId, n, H1)
	QB := new(sm9curve.G1).ScalarBaseMult(t1)
	QB = new(sm9curve.G1).Add(QB, key)
	r, _ := randFieldElement(rand.Reader, n)
	C1 := new(sm9curve.G1).ScalarMult(QB, r)
	g := sm9curve.Pair(key, sm9curve.Gen2)
	w := new(sm9curve.GT).ScalarMult(g, r)
	klen := len(m) + 32
	var t []byte
	t = append(t, C1.Marshal()...)
	t = append(t, w.Marshal()...)
	t = append(t, id...)
	k := KDF(t, klen)
	k1 := k[:len(m)]
	k2 := k[len(m) : len(m)+32]
	C2 := XOR(m, k1)
	C3 := MAC(k2, C2)
	res := &Sm9Enc{
		C1: C1,
		C3: C3,
		C2: C2,
	}
	return res
}

func Decrypt(enc *Sm9Enc, id []byte, deb *sm9curve.G2) []byte {
	C1 := enc.C1
	C3 := enc.C3
	C2 := enc.C2
	wPrime := sm9curve.Pair(C1, deb)
	klen := len(C2) + 32
	var t []byte
	t = append(t, C1.Marshal()...)
	t = append(t, wPrime.Marshal()...)
	t = append(t, id...)
	kPrime := KDF(t, klen)
	k1Prime := kPrime[:len(C2)]
	k2Prime := kPrime[len(C2) : len(C2)+32]
	mPrime := XOR(C2, k1Prime)
	u := MAC(k2Prime, C2)
	if string(u) != string(C3) {
		panic("not equal")
	}

	return mPrime
}
