package cert

import (
	"ced-paper/CED-Authentication/_const"
	"ced-paper/CED-Authentication/elliptic/sm9curve"
	"ced-paper/CED-Authentication/sm/sm9"
	"crypto/rand"
)

func GenMasterKey() (*sm9.MasterKey, error) {
	return sm9.MasterKeyGen(rand.Reader)
}

func GenUserKey(mk *sm9.MasterKey, id string) (*sm9.UserKey, error) {
	return sm9.UserKeyGen(mk, []byte(id), _const.H_Id)
}

func Sign(uk *sm9.UserKey, mpk *sm9curve.G2, msg []byte) (*sm9.Sm9Sig, error) {
	return sm9.Sign(uk, mpk, msg)
}
