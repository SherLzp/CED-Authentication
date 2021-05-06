package contract

import (
	"ced-paper/CED-Authentication/_const"
	"ced-paper/CED-Authentication/_rpc"
	"ced-paper/CED-Authentication/cert"
	"crypto/ecdsa"
	"crypto/x509"
)

var (
	Cli         *_rpc.ProviderClient
	AuthCli     *_rpc.AuthClient
	Instance    *Storage
	Certificate *x509.Certificate
	CaSk        *ecdsa.PrivateKey
)

func init() {
	var err error
	Cli, err = _rpc.NewClient(_const.InfuraRinkebyNetwork)
	if err != nil {
		panic(err)
	}
	AuthCli, err = _rpc.NewAuthClient(Cli, _const.RinkebySuperSk)
	if err != nil {
		panic(err)
	}
	Instance, err = LoadStorageInstance(Cli, _const.StorageAddress)
	if err != nil {
		panic(err)
	}
	Certificate, _, CaSk = cert.GenCARoot()
}
