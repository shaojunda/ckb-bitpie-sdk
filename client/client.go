package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/shaojunda/ckb-bitpie-sdk/utils"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/nervosnetwork/ckb-sdk-go/crypto/blake2b"
	"github.com/nervosnetwork/ckb-sdk-go/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	"github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
)

func NewRpcClient(endpoint string) (rpc.Client, error) {
	return rpc.DialWithIndexer(endpoint+"/rpc", endpoint+"/indexer")
}

func transaction2TxDict(rawTx *types.Transaction, blockNumber uint64, blockTime time.Time, client rpc.Client, config *config.Config) (result *tx.Dict, err error) {
	result = &tx.Dict{
		TxHash:  rawTx.Hash.String(),
		TxAt:    blockTime,
		BlockNo: blockNumber,
	}

	for i, input := range rawTx.Inputs {
		// ignore cellbase
		if input.PreviousOutput.TxHash.String() == "0x0000000000000000000000000000000000000000000000000000000000000000" {
			continue
		}

		previous, err := client.GetTransaction(context.Background(), input.PreviousOutput.TxHash)
		if err != nil {
			return nil, err
		}

		cell := previous.Transaction.Outputs[input.PreviousOutput.Index]

		var addr string
		if config.Network == "mainnet" {
			addr, err = address.Generate(address.Mainnet, cell.Lock)
		} else {
			addr, err = address.Generate(address.Testnet, cell.Lock)
		}
		if err != nil {
			return nil, err
		}

		if cell.Type != nil && cell.Type.CodeHash.String() == config.UDT.Script.CodeHash {
			uuid := "0x" + hex.EncodeToString(cell.Type.Args)
			b := previous.Transaction.OutputsData[input.PreviousOutput.Index]
			for i := 0; i < len(b)/2; i++ {
				b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
			}
			amount := big.NewInt(0).SetBytes(b)

			if token, ok := config.UDT.Tokens[uuid]; ok {
				result.Inputs = append(result.Inputs, tx.Input{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       token.Symbol,
					TokenIdentifier: uuid,
					TokenDecimal:    token.Decimal,
				})
			} else {
				result.Inputs = append(result.Inputs, tx.Input{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       "",
					TokenIdentifier: uuid,
					TokenDecimal:    0,
				})
			}
		}
		result.Inputs = append(result.Inputs, tx.Input{
			Value:   fmt.Sprintf("%d", cell.Capacity),
			Address: addr,
			Sn:      i,
		})
	}

	for i, output := range rawTx.Outputs {
		var addr string
		if config.Network == "mainnet" {
			addr, err = address.Generate(address.Mainnet, output.Lock)
		} else {
			addr, err = address.Generate(address.Testnet, output.Lock)
		}
		if err != nil {
			return nil, err
		}

		if output.Type != nil && output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
			uuid := "0x" + hex.EncodeToString(output.Type.Args)
			b := rawTx.OutputsData[i]
			for i := 0; i < len(b)/2; i++ {
				b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
			}
			amount := big.NewInt(0).SetBytes(b)

			if token, ok := config.UDT.Tokens[uuid]; ok {
				result.Outputs = append(result.Outputs, tx.Output{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       token.Symbol,
					TokenIdentifier: uuid,
					TokenDecimal:    token.Decimal,
				})
			} else {
				result.Outputs = append(result.Outputs, tx.Output{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       "",
					TokenIdentifier: uuid,
					TokenDecimal:    0,
				})
			}
		}
		result.Outputs = append(result.Outputs, tx.Output{
			Value:   fmt.Sprintf("%d", output.Capacity),
			Address: addr,
			Sn:      i,
		})
	}

	return
}

func offlineTransaction2TxDict(inputs []tx.Input, rawTx *types.Transaction, config *config.Config) (result *tx.Dict, err error) {
	result = &tx.Dict{}

	for i, input := range inputs {
		input.Sn = i
		result.Inputs = append(result.Inputs, input)
	}

	for i, output := range rawTx.Outputs {
		var addr string
		if config.Network == "mainnet" {
			addr, err = address.Generate(address.Mainnet, output.Lock)
		} else {
			addr, err = address.Generate(address.Testnet, output.Lock)
		}
		if err != nil {
			return nil, err
		}

		if output.Type != nil && output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
			uuid := "0x" + hex.EncodeToString(output.Type.Args)
			b := rawTx.OutputsData[i]
			for i := 0; i < len(b)/2; i++ {
				b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
			}
			amount := big.NewInt(0).SetBytes(b)

			if token, ok := config.UDT.Tokens[uuid]; ok {
				result.Inputs = append(result.Inputs, tx.Input{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       token.Symbol,
					TokenIdentifier: uuid,
					TokenDecimal:    token.Decimal,
				})
			} else {
				result.Inputs = append(result.Inputs, tx.Input{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       token.Symbol,
					TokenIdentifier: "Unknown",
					TokenDecimal:    1,
				})
			}
		} else {
			result.Outputs = append(result.Outputs, tx.Output{
				Value:   fmt.Sprintf("%d", output.Capacity),
				Address: addr,
				Sn:      i,
			})
		}
	}

	return
}

func GetTransaction(txHash string, client rpc.Client, config *config.Config) (*tx.Dict, error) {
	rawTx, err := client.GetTransaction(context.Background(), types.HexToHash(txHash))
	if err != nil {
		return nil, err
	}
	tNow := time.Now()
	timeT := time.Unix(tNow.Unix(), 0)
	if rawTx.TxStatus == nil || rawTx.TxStatus.BlockHash == nil {
		return transaction2TxDict(rawTx.Transaction, 0, timeT, client, config)
	} else {
		block, err := client.GetHeader(context.Background(), *rawTx.TxStatus.BlockHash)
		if err != nil {
			return nil, err
		}

		return transaction2TxDict(rawTx.Transaction, block.Number, time.Unix(int64(block.Timestamp/1000), int64(block.Timestamp%1000)), client, config)
	}
}

func LockScript2Address(script *types.Script, config *config.Config) (addr string, err error) {
	if config.Network == "mainnet" {
		addr, err = address.Generate(address.Mainnet, script)
	} else {
		addr, err = address.Generate(address.Testnet, script)
	}
	return
}

func Pubkey2Address(pub string, isAcp bool, config *config.Config) (addr string, err error) {
	args, err := blake2b.Blake160(common.FromHex(pub))
	if err != nil {
		return "", err
	}

	var script *types.Script

	if !isAcp {
		script = &types.Script{
			CodeHash: types.HexToHash(transaction.SECP256K1_BLAKE160_SIGHASH_ALL_TYPE_HASH),
			HashType: types.HashTypeType,
			Args:     args,
		}
	} else {
		script = &types.Script{
			CodeHash: types.HexToHash(config.ACP.Script.CodeHash),
			HashType: types.ScriptHashType(config.ACP.Script.HashType),
			Args:     args,
		}
	}

	return LockScript2Address(script, config)
}

func Address2LockScript(addr string) (*types.Script, error) {
	parsedAddress, err := address.Parse(addr)
	if err != nil {
		return nil, err
	}

	return parsedAddress.Script, nil
}

func GetBlockCount(client rpc.Client) (uint64, error) {
	header, err := client.GetTipHeader(context.Background())
	if err != nil {
		return 0, err
	}
	return header.Number, nil
}

func GetBlockTxs(blockNo uint64, client rpc.Client, config *config.Config) ([]*tx.Dict, error) {
	block, err := client.GetBlockByNumber(context.Background(), blockNo)
	if err != nil {
		return nil, err
	}

	result := make([]*tx.Dict, 0)

	for _, rawTx := range block.Transactions {
		dict, err := transaction2TxDict(rawTx, blockNo, time.Unix(int64(block.Header.Timestamp/1000), int64(block.Header.Timestamp%1000)), client, config)
		if err != nil {
			return nil, err
		}
		result = append(result, dict)
	}

	return result, nil
}

func BalanceForAddress(addr string, client rpc.Client) (*Balance, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, err
	}

	searchKey := &indexer.SearchKey{
		Script:     parsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}

	var balance uint64
	var cursor string

	for {
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, 1000, cursor)
		if err != nil {
			return nil, err
		}

		for _, cell := range liveCells.Objects {
			if len(cell.OutputData) == 0 && cell.Output.Type == nil {
				balance += cell.Output.Capacity
			}
		}

		if len(liveCells.Objects) < 1000 || liveCells.LastCursor == "" {
			break
		}
		cursor = liveCells.LastCursor
	}

	return &Balance{
		Balance: fmt.Sprintf("%d", balance),
	}, nil
}

func BalancesForAddress(addr string, client rpc.Client, config *config.Config) ([]*Balance, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, err
	}

	balanceMap := make(map[string]*Balance)
	balanceMap["CKB"] = &Balance{
		Balance: "0",
	}
	for key, token := range config.UDT.Tokens {
		balanceMap[key] = &Balance{
			TokenCode:       token.Symbol,
			TokenIdentifier: key,
			TokenDecimal:    token.Decimal,
			Balance:         big.NewInt(0).String(),
		}
	}

	searchKey := &indexer.SearchKey{
		Script:     parsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}

	var cursor string
	for {
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, 1000, cursor)
		if err != nil {
			return nil, err
		}

		for _, cell := range liveCells.Objects {
			if len(cell.OutputData) == 0 && cell.Output.Type == nil {
				ckb := balanceMap["CKB"]
				balance, _ := strconv.ParseUint(ckb.Balance, 10, 64)
				balance += cell.Output.Capacity
				ckb.Balance = fmt.Sprintf("%d", balance)
			}
			if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
				uuid := "0x" + hex.EncodeToString(cell.Output.Type.Args)
				if token, ok := balanceMap[uuid]; ok {
					b := cell.OutputData
					for i := 0; i < len(b)/2; i++ {
						b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
					}
					amount := big.NewInt(0).SetBytes(b)
					balance, _ := big.NewInt(0).SetString(token.Balance, 10)
					balance = big.NewInt(0).Add(balance, amount)
					token.Balance = balance.String()
				}
			}

		}

		if len(liveCells.Objects) < 1000 || liveCells.LastCursor == "" {
			break
		}
		cursor = liveCells.LastCursor
	}

	result := make([]*Balance, 0)

	for _, balance := range balanceMap {
		result = append(result, balance)
	}

	return result, nil
}

func TxsForAddress(addr string, cursor string, limit uint64, client rpc.Client, config *config.Config) (*AddressTxs, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, err
	}

	searchKey := &indexer.SearchKey{
		Script:     parsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}

	rawTxs, err := client.GetTransactions(context.Background(), searchKey, indexer.SearchOrderDesc, limit, cursor)
	if err != nil {
		return nil, err
	}

	var result = &AddressTxs{
		Txs:    make([]*tx.Dict, len(rawTxs.Objects)),
		Cursor: rawTxs.LastCursor,
	}

	for i, rawTx := range rawTxs.Objects {
		dict, err := GetTransaction(rawTx.TxHash.String(), client, config)
		if err != nil {
			return nil, err
		}

		result.Txs[i] = dict
	}

	return result, nil
}

func IsAcpAddress(addr string, config *config.Config) (bool, error) {
	return utils.IsAcpAddress(addr, config)
}

func IsOldAcpAddress(addr string, config *config.Config) (bool, error) {
	return utils.IsOldAcpAddress(addr, config)
}
