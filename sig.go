package main

import (
	"crypto/rand"
	"github.com/xlcetc/cryptogm/sm/sm9"
)

func GenMasterKey() (*sm9.MasterKey, error) {
	return sm9.MasterKeyGen(rand.Reader)
}

func GenUserKey(mk *sm9.MasterKey) (*sm9.UserKey, error) {
	return sm9.UserKeyGen(mk, Edge_Id, H_Id)
}

func Sign(uk *sm9.UserKey, mpk *sm9.MasterPubKey, msg []byte) (*sm9.Sm9Sig, error) {
	return sm9.Sign(uk, mpk, msg)
}
