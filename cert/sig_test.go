package cert

import (
	"ced-paper/CED-Authentication/sm/sm9"
	"fmt"
	"testing"
)

func TestGenUserKey(t *testing.T) {
	mk := sm9.Mk()
	//err := newMk.UnmarshalJSON(mkBytes)
	uk2 := sm9.Uk2()
	enc := sm9.Encrypt(mk.MEncPk, []byte("tttt"), []byte("Edge_B"), 1)
	res := sm9.Decrypt(enc, []byte("Edge_B"), uk2.EncSk)
	fmt.Println(string(res))
}
