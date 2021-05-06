package contract

import (
	"ced-paper/CED-Authentication/_const"
	"ced-paper/CED-Authentication/_rpc"
	"context"
	"fmt"
	"testing"
)

func TestDeploy(t *testing.T) {
	cli, _ := _rpc.NewClient(_const.InfuraRinkebyNetwork)
	defer cli.Close()
	authCli, _ := _rpc.NewAuthClient(cli, _const.RinkebySuperSk)
	gasPrice, _ := cli.SuggestGasPrice(context.Background())
	addr, _, err := DeployStorageContract(cli, authCli, gasPrice, _const.SuggestHighGasLimit)
	if err != nil {
		panic(err)
	}
	fmt.Println(addr)
}

func TestStore(t *testing.T) {
	cli, _ := _rpc.NewClient(_const.InfuraRinkebyNetwork)
	defer cli.Close()
	authCli, _ := _rpc.NewAuthClient(cli, _const.RinkebySuperSk)
	gasPrice, _ := cli.SuggestGasPrice(context.Background())
	instance, err := LoadStorageInstance(cli, _const.StorageAddress)
	if err != nil {
		panic(err)
	}
	txHash, err := Store(cli, authCli, instance, "test", gasPrice, _const.SuggestHighGasLimit)
	if err != nil {
		panic(err)
	}
	fmt.Println(txHash)
	receipt, err := cli.GetTransactionReceipt(txHash)
	if err != nil {
		panic(err)
	}
	fmt.Println(receipt)
}

func TestReadStorage(t *testing.T) {
	cli, _ := _rpc.NewClient(_const.InfuraRinkebyNetwork)
	defer cli.Close()
	authCli, _ := _rpc.NewAuthClient(cli, _const.RinkebySuperSk)
	gasPrice, _ := cli.SuggestGasPrice(context.Background())
	instance, err := LoadStorageInstance(cli, _const.StorageAddress)
	if err != nil {
		panic(err)
	}
	s, err := ReadStorage(cli, authCli, instance, gasPrice, _const.SuggestHighGasLimit)
	if err != nil {
		panic(err)
	}
	fmt.Println(s)
}
