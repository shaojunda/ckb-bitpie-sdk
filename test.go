package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/ququzone/ckb-bitpie-sdk/client"
	"github.com/ququzone/ckb-bitpie-sdk/config"
	"github.com/ququzone/ckb-sdk-go/crypto/secp256k1"
	"github.com/ququzone/ckb-sdk-go/rpc"
	"github.com/ququzone/ckb-sdk-go/transaction"
)

func main() {
	// step 0: init config
	c, _ := config.Load("config-example.yaml")

	// step 1: init rpc client
	cli, err := client.NewRpcClient(c.Rpc)
	if err != nil {
		log.Println(err)
	}

	fmt.Println(client.IsAcpAddress("ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyk6dhveldhcyv7x2pxyp0etw983n7xnahzhxzeer", c))
	fmt.Println(client.IsAcpAddress("ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", c))

	// step 2: print tip header
	header, _ := cli.GetTipHeader(context.Background())
	fmt.Printf("tip header: %d\n", header.Number)

	// step 3: print transaction
	tx, _ := client.GetTransaction("0xb1c236f76b4ae3496ab4b30331b7de76eb3894ee436b9cc2714641b9f5925791", cli, c)
	bytes, _ := json.Marshal(tx)
	fmt.Printf("transcation 0xb1c236f76b4ae3496ab4b30331b7de76eb3894ee436b9cc2714641b9f5925791: %s\n", string(bytes))

	// step 4: pubkey to address
	address, _ := client.Pubkey2Address("0x020ea44dd70b0116ab44ade483609973adf5ce900d7365d988bc5f352b68abe50b", false, c)
	fmt.Printf("secp256k1 address: %s\n", address)
	address, _ = client.Pubkey2Address("0x020ea44dd70b0116ab44ade483609973adf5ce900d7365d988bc5f352b68abe50b", true, c)
	fmt.Printf("acp address: %s\n", address)

	// step 5: GetBlockCount
	count, _ := client.GetBlockCount(cli)
	fmt.Printf("block count: %d\n", count)

	// step 6: GetBlockTxs
	txs, _ := client.GetBlockTxs(3829, cli, c)
	bytes, _ = json.Marshal(txs)
	fmt.Printf("block 3829: %s\n", string(bytes))

	// step 6: balance for address
	balance, _ := client.BalanceForAddress("ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", cli)
	bytes, _ = json.Marshal(balance)
	fmt.Printf("address ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k balance: %s\n", string(bytes))

	// step 7: balances for address
	balances, _ := client.BalancesForAddress("ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", cli, c)
	bytes, _ = json.Marshal(balances)
	fmt.Printf("address ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k balances: %s\n", string(bytes))

	// step 8: txs for address
	addrTxs, _ := client.TxsForAddress("ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", "", cli, c)
	bytes, _ = json.Marshal(addrTxs)
	fmt.Printf("address ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k txs: %s\n", string(bytes))

	// step 9: build transform account transaction
	//t, err := client.BuildTransformAccountTransaction("ckt1qyq0zcxc08wscs29zuq76zlyrqlts3qzfkhs5wjs3f", cli, c)
	//if err != nil {
	//	log.Fatalf("build transform account transaction error: %v\n", err)
	//}
	//key, _ := secp256k1.HexToKey("_________")
	//_ = transaction.SingleSegmentSignTransaction(t, 0, len(t.Witnesses), transaction.EmptyWitnessArg, key)
	//hash, _ := cli.SendTransaction(context.Background(), t)
	//fmt.Printf("transform account transaction: %s\n", hash.String())

	// step 10: build create udt cell transaction
	//t, err := client.BuildUdtCellTransaction("ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhutqmpua6rzpg5tsrmgtusvrawzyqfx67r07p6t", "USDT", cli, c)
	//if err != nil {
	//	log.Fatalf("build transaction error: %v\n", err)
	//}
	//key, _ := secp256k1.HexToKey("_________")
	//_ = transaction.SingleSegmentSignTransaction(t, 0, len(t.Witnesses), transaction.EmptyWitnessArg, key)
	//hash, err := cli.SendTransaction(context.Background(), t)
	//if err != nil {
	//	fmt.Println(rpc.TransactionString(t))
	//	log.Fatalf("send transaction error: %v\n", err)
	//}
	//fmt.Printf("transform account transaction: %s\n", hash.String())

	// step 11: build transfer
	t, _, err := client.BuildNormalTransaction("ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyk6dhveldhcyv7x2pxyp0etw983n7xnahzhxzeer", "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhutqmpua6rzpg5tsrmgtusvrawzyqfx67r07p6t", "50000", "USDT", cli, c)
	if err != nil {
		log.Fatalf("build transaction error: %v\n", err)
	}
	key, _ := secp256k1.HexToKey("_________")

	// message, _ := transaction.SingleSegmentSignMessage(t, 1, len(t.Witnesses), transaction.EmptyWitnessArg)
	_ = transaction.SingleSegmentSignTransaction(t, 1, len(t.Witnesses), transaction.EmptyWitnessArg, key)
	hash, err := cli.SendTransaction(context.Background(), t)
	if err != nil {
		fmt.Println(rpc.TransactionString(t))
		log.Fatalf("send transaction error: %v\n", err)
	}
	fmt.Printf("transform account transaction: %s\n", hash.String())
}
