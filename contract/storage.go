package contract

import (
	"ced-paper/CED-Authentication/_rpc"
	"context"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

func DeployStorageContract(cli *_rpc.ProviderClient, authCli *_rpc.AuthClient, gasPrice *big.Int, gasLimit uint64) (addr string, txHash string, err error) {
	transactOpts, err := ConstructTransactOpts(cli, authCli, gasPrice, gasLimit)
	if err != nil {
		return "", "", err
	}
	address, tx, _, err := DeployStorage(transactOpts, *cli)
	if err != nil {
		return "", "", err
	}
	return address.Hex(), tx.Hash().Hex(), nil
}

func LoadStorageInstance(cli *_rpc.ProviderClient, addr string) (storageInstance *Storage, err error) {
	storageInstance, err = NewStorage(common.HexToAddress(addr), *cli)
	return storageInstance, err
}

func Store(cli *_rpc.ProviderClient, authCli *_rpc.AuthClient, instance *Storage, value string, gasPrice *big.Int, gasLimit uint64) (txHash string, err error) {
	transactOpts, err := ConstructTransactOpts(cli, authCli, gasPrice, gasLimit)
	if err != nil {
		return "", err
	}
	tx, err := instance.Store(transactOpts, value)
	if err != nil {
		return "", err
	}
	return tx.Hash().Hex(), nil
}

func ReadStorage(cli *_rpc.ProviderClient, authCli *_rpc.AuthClient, instance *Storage, gasPrice *big.Int, gasLimit uint64) (string, error) {
	opts := bind.CallOpts{Pending: false, Context: context.Background()}
	value, err := instance.Retrieve(&opts)
	return value, err
}

func ConstructTransactOpts(cli *_rpc.ProviderClient, authCli *_rpc.AuthClient, gasPrice *big.Int, gasLimit uint64) (transactOpts *bind.TransactOpts, err error) {
	transactOpts, err = bind.NewKeyedTransactorWithChainID(authCli.PrivateKey, authCli.ChainId)
	if err != nil {
		return nil, err
	}
	nonce, err := cli.GetPendingNonce(authCli.Address.Hex())
	if err != nil {
		return nil, err
	}
	transactOpts.Nonce = big.NewInt(int64(nonce))
	transactOpts.GasPrice = gasPrice
	transactOpts.GasLimit = gasLimit
	transactOpts.Value = big.NewInt(0)
	return transactOpts, nil
}
