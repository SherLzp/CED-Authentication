package sm9

import (
	"ced-paper/CED-Authentication/elliptic/sm9curve"
	"encoding/hex"
	"encoding/json"
	"math/big"
)

//MasterKey contains a master secret key and a master public key.
type MasterKey struct {
	Msk    *big.Int
	MEncSk *big.Int
	Mpk    *sm9curve.G2
	MEncPk *sm9curve.G1
}

func (key *MasterKey) MarshalJSON() ([]byte, error) {
	res := map[string]string{}
	res["Msk"] = BigIntToStr(key.Msk)
	res["MEncSk"] = BigIntToStr(key.MEncSk)
	res["Mpk"] = sm9curve.G2ToStr(key.Mpk)
	res["MEncPk"] = sm9curve.G1ToStr(key.MEncPk)
	return json.Marshal(res)
}

func (key *MasterKey) UnmarshalJSON(data []byte) error {
	res := map[string]string{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}
	key.Msk = StrToBigInt(res["Msk"])
	key.MEncSk = StrToBigInt(res["MEncSk"])
	key.Mpk = sm9curve.StrToG2(res["Mpk"])
	key.MEncPk = sm9curve.StrToG1(res["MEncPk"])
	return nil
}

//UserKey contains a secret key.
type UserKey struct {
	Sk    *sm9curve.G1
	EncSk *sm9curve.G2
}

func (key *UserKey) MarshalJSON() ([]byte, error) {
	res := map[string]string{}
	res["Sk"] = sm9curve.G1ToStr(key.Sk)
	res["EncSk"] = sm9curve.G2ToStr(key.EncSk)
	return json.Marshal(res)
}

func (key *UserKey) UnmarshalJSON(data []byte) error {
	res := map[string]string{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}
	skBytes, _ := hex.DecodeString(res["Sk"])
	Sk := new(sm9curve.G1)
	_, err = Sk.Unmarshal(skBytes)
	if err != nil {
		return err
	}
	key.Sk = sm9curve.StrToG1(res["Sk"])
	key.EncSk = sm9curve.StrToG2(res["EncSk"])
	return nil

}

//Sm9Sig contains a big number and an element in G1.
type Sm9Sig struct {
	H *big.Int
	S *sm9curve.G1
}

type Sm9Enc struct {
	C1 *sm9curve.G1
	C3 []byte
	C2 []byte
}

func (enc *Sm9Enc) MarshalJSON() ([]byte, error) {
	res := map[string]string{}
	res["C1"] = sm9curve.G1ToStr(enc.C1)
	res["C3"] = hex.EncodeToString(enc.C3)
	res["C2"] = hex.EncodeToString(enc.C2)
	return json.Marshal(res)
}

func (enc *Sm9Enc) UnmarshalJSON(data []byte) error {
	res := map[string]string{}
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}
	enc.C1 = sm9curve.StrToG1(res["C1"])
	enc.C3, _ = hex.DecodeString(res["C3"])
	enc.C2, _ = hex.DecodeString(res["C2"])
	return nil
}
