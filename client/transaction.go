package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/ququzone/ckb-bitpie-sdk/config"
	btx "github.com/ququzone/ckb-bitpie-sdk/utils/tx"
	"github.com/ququzone/ckb-rich-sdk-go/indexer"
	"github.com/ququzone/ckb-rich-sdk-go/rpc"
	"github.com/ququzone/ckb-sdk-go/address"
	orpc "github.com/ququzone/ckb-sdk-go/rpc"
	"github.com/ququzone/ckb-sdk-go/transaction"
	"github.com/ququzone/ckb-sdk-go/types"
	"github.com/ququzone/ckb-sdk-go/utils"
)

const (
	MaxInput    uint64 = 1000
	FeeRate     uint64 = 1000
	CkbCapacity uint64 = 6100000000
	UdtCapacity uint64 = 14200000000
)

var (
	ErrInsufficientCkbBalance  = errors.New("insufficient CKB balance")
	ErrInsufficientSudtBalance = errors.New("insufficient sUDT balance")
	ErrNotAcpLock              = errors.New("address must acp address")
	ErrUnknownToken            = errors.New("unknown token")
	ErrNoneAcpCell             = errors.New("none acy cell")
)

func BuildNormalTransaction(from string, to string, amount string, tokenIdentifier string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	fromParsedAddr, err := address.Parse(from)
	if err != nil {
		return nil, nil, err
	}
	toParsedAddr, err := address.Parse(to)
	if err != nil {
		return nil, nil, err
	}

	if tokenIdentifier != "" {
		return buildUdtTransaction(from, to, fromParsedAddr.Script, toParsedAddr.Script, amount, tokenIdentifier, client, config)
	}

	return buildCkbTransaction(from, to, fromParsedAddr.Script, toParsedAddr.Script, amount, client, config)
}

func buildCkbTransaction(fromAddr string, toAddr string, from *types.Script, to *types.Script, amount string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	var total uint64
	total, _ = strconv.ParseUint(amount, 10, 64)

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}
	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: types.DepType(config.ACP.Deps[0].DepType),
	}

	inputs := make([]btx.Input, 0)
	var toCapacity, fromCapacity uint64

	if to.CodeHash.String() == config.ACP.Script.CodeHash {
		searchKey := &indexer.SearchKey{
			Script:     to,
			ScriptType: indexer.ScriptTypeLock,
		}
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
		if err != nil {
			return nil, nil, err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				toCapacity = cell.Output.Capacity
				tx.Inputs = append(tx.Inputs, &types.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})

				inputs = append(inputs, btx.Input{
					Value:   fmt.Sprintf("%d", cell.Output.Capacity),
					Address: toAddr,
				})
				tx.Witnesses = append(tx.Witnesses, []byte{})
				break
			}
		}
	}
	toNormal := false
	if len(tx.Inputs) == 0 {
		if total < CkbCapacity {
			return nil, nil, ErrNoneAcpCell
		}
		toNormal = true
	}

	searchKey := &indexer.SearchKey{
		Script:     from,
		ScriptType: indexer.ScriptTypeLock,
	}

	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			if cell.Output.Capacity < total+CkbCapacity {
				return nil, nil, ErrInsufficientCkbBalance
			}
			fromCapacity = cell.Output.Capacity
			tx.Inputs = append(tx.Inputs, &types.CellInput{
				Since:          0,
				PreviousOutput: cell.OutPoint,
			})
			inputs = append(inputs, btx.Input{
				Value:   fmt.Sprintf("%d", cell.Output.Capacity),
				Address: fromAddr,
			})
			tx.Witnesses = append(tx.Witnesses, []byte{})
			break
		}
	}

	if fromCapacity == 0 {
		return nil, nil, ErrInsufficientCkbBalance
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()

	if toNormal {
		tx.Witnesses[0] = emptyWitness
	} else {
		tx.Witnesses[1] = emptyWitness
	}

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: toCapacity + total,
		Lock:     to,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 0,
		Lock:     from,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})
	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	if err != nil {
		return nil, nil, err
	}
	tx.Outputs[1].Capacity = fromCapacity - total - fee

	if tx.Outputs[1].Capacity < CkbCapacity {
		return nil, nil, ErrInsufficientCkbBalance
	}

	return tx, inputs, nil
}

func buildUdtTransaction(fromAddr string, toAddr string, from *types.Script, to *types.Script, amount string, tokenIdentifier string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	var uuid string
	var decimals int
	var symbol string
	for key, token := range config.UDT.Tokens {
		if key == tokenIdentifier {
			uuid = key
			symbol = token.Symbol
			decimals = token.Decimal
			break
		}
	}
	if uuid == "" {
		return nil, nil, ErrUnknownToken
	}

	inputs := make([]btx.Input, 0)
	var total *big.Int
	total, _ = big.NewInt(0).SetString(amount, 10)
	var origin *big.Int
	var originToCKB uint64
	var originFromCKB uint64

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}
	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: types.DepType(config.ACP.Deps[0].DepType),
	}
	tx.CellDeps = append(tx.CellDeps, &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.UDT.Deps[0].TxHash),
			Index:  config.UDT.Deps[0].Index,
		},
		DepType: types.DepType(config.UDT.Deps[0].DepType),
	})

	if to.CodeHash.String() == config.ACP.Script.CodeHash {
		searchKey := &indexer.SearchKey{
			Script:     to,
			ScriptType: indexer.ScriptTypeLock,
		}
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
		if err != nil {
			return nil, nil, err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
				args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
				if uuid == args {
					originToCKB = cell.Output.Capacity
					tx.Inputs = append(tx.Inputs, &types.CellInput{
						Since:          0,
						PreviousOutput: cell.OutPoint,
					})
					b := cell.OutputData
					for i := 0; i < len(b)/2; i++ {
						b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
					}
					origin = big.NewInt(0).SetBytes(b)

					inputs = append(inputs, btx.Input{
						Value:           origin.String(),
						Address:         toAddr,
						TokenCode:       symbol,
						TokenIdentifier: tokenIdentifier,
						TokenDecimal:    decimals,
					})
					tx.Witnesses = append(tx.Witnesses, []byte{})
					break
				}
			}
		}
		if len(tx.Inputs) == 0 {
			return nil, nil, ErrNoneAcpCell
		}
	}

	toNormal := false
	if len(tx.Inputs) == 0 {
		origin = big.NewInt(0)
		originToCKB = UdtCapacity
		toNormal = true
	}

	searchKey := &indexer.SearchKey{
		Script:     from,
		ScriptType: indexer.ScriptTypeLock,
	}
	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return nil, nil, err
	}

	stopCkb := false
	stopUdt := false
	var ckbBalance uint64
	var udtBalance *big.Int
	for _, cell := range liveCells.Objects {
		if toNormal && cell.Output.Type == nil && len(cell.OutputData) == 0 {
			if (cell.Output.Capacity <= CkbCapacity*2) || (!toNormal && cell.Output.Capacity <= CkbCapacity) {
				return nil, nil, ErrInsufficientCkbBalance
			}
		}
		if !stopUdt && cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
			args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
			if uuid == args {
				b := cell.OutputData
				for i := 0; i < len(b)/2; i++ {
					b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
				}
				udtBalance = big.NewInt(0).SetBytes(b)
				originFromCKB = cell.Output.Capacity

				if udtBalance.Cmp(total) < 0 {
					continue
				}

				tx.Inputs = append(tx.Inputs, &types.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				inputs = append(inputs, btx.Input{
					Value:           udtBalance.String(),
					Address:         fromAddr,
					TokenCode:       symbol,
					TokenIdentifier: tokenIdentifier,
					TokenDecimal:    decimals,
				})
				tx.Witnesses = append(tx.Witnesses, []byte{})
				stopUdt = true
			}
		}
		if stopUdt {
			break
		}
	}

	if !stopUdt {
		return nil, nil, ErrInsufficientSudtBalance
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	if toNormal {
		tx.Witnesses[0] = emptyWitness
	} else {
		tx.Witnesses[1] = emptyWitness
	}

	udtArgs, _ := hex.DecodeString(uuid[2:])
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: originToCKB,
		Lock:     to,
		Type: &types.Script{
			CodeHash: types.HexToHash(config.UDT.Script.CodeHash),
			HashType: types.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	origin = big.NewInt(0).Add(total, origin)
	b := origin.Bytes()
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	if len(b) < 16 {
		for i := len(b); i < 16; i++ {
			b = append(b, 0)
		}
	}
	tx.OutputsData = append(tx.OutputsData, b)

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: originFromCKB,
		Lock:     from,
		Type: &types.Script{
			CodeHash: types.HexToHash(config.UDT.Script.CodeHash),
			HashType: types.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	b = big.NewInt(0).Sub(udtBalance, total).Bytes()
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	if len(b) < 16 {
		for i := len(b); i < 16; i++ {
			b = append(b, 0)
		}
	}
	tx.OutputsData = append(tx.OutputsData, b)

	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	fee += 8
	if err != nil {
		return nil, nil, err
	}
	originFromCKBBalance := tx.Outputs[1].Capacity
	if originFromCKBBalance-fee < UdtCapacity {
		for _, cell := range liveCells.Objects {
			if !stopCkb && cell.Output.Type == nil && len(cell.OutputData) == 0 {
				if (toNormal && cell.Output.Capacity <= CkbCapacity*2) || (!toNormal && cell.Output.Capacity <= CkbCapacity) {
					return nil, nil, ErrInsufficientCkbBalance
				}
				tx.Inputs = append(tx.Inputs, &types.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				tx.Witnesses = append(tx.Witnesses, []byte{})
				ckbBalance = cell.Output.Capacity
				stopCkb = true
			}
			if stopCkb {
				break
			}
		}

		if !stopCkb {
			return nil, nil, ErrInsufficientCkbBalance
		}

		tx.Outputs = append(tx.Outputs, &types.CellOutput{
			Capacity: 0,
			Lock:     from,
		})
		tx.OutputsData = append(tx.OutputsData, []byte{})
		fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
		fee += 8
		if err != nil {
			return nil, nil, err
		}
		tx.Outputs[2].Capacity = ckbBalance - fee
		if toNormal {
			tx.Outputs[2].Capacity = ckbBalance - UdtCapacity - fee
		}
	} else {
		tx.Outputs[1].Capacity = originFromCKBBalance - fee
	}

	return tx, inputs, nil
}

func BuildEmptyTransaction(from string, to string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	fromParsedAddr, err := address.Parse(from)
	if err != nil {
		return nil, nil, err
	}
	toParsedAddr, err := address.Parse(to)
	if err != nil {
		return nil, nil, err
	}

	inputs := make([]btx.Input, 0)
	searchKey := &indexer.SearchKey{
		Script:     fromParsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}

	tx := transaction.NewSecp256k1SingleSigTx(scripts)

	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	if len(liveCells.Objects) == 0 {
		return nil, nil, ErrInsufficientCkbBalance
	}

	var balance uint64 = 0
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			tx.Inputs = append(tx.Inputs, &types.CellInput{
				Since:          0,
				PreviousOutput: cell.OutPoint,
			})

			inputs = append(inputs, btx.Input{
				Value:   fmt.Sprintf("%d", cell.Output.Capacity),
				Address: from,
			})
			tx.Witnesses = append(tx.Witnesses, []byte{})
			balance += cell.Output.Capacity
		}
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	tx.Witnesses[0] = emptyWitness

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 0,
		Lock:     toParsedAddr.Script,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})

	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	if err != nil {
		return nil, nil, err
	}

	tx.Outputs[0].Capacity = balance - fee

	return tx, inputs, nil
}

func BuildTransformAccountTransaction(addr string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, nil, err
	}

	inputs := make([]btx.Input, 0)
	searchKey := &indexer.SearchKey{
		Script:     parsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}

	tx := transaction.NewSecp256k1SingleSigTx(scripts)

	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	if len(liveCells.Objects) == 0 {
		return nil, nil, ErrInsufficientCkbBalance
	}

	var balance uint64 = 0
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			tx.Inputs = append(tx.Inputs, &types.CellInput{
				Since:          0,
				PreviousOutput: cell.OutPoint,
			})
			inputs = append(inputs, btx.Input{
				Value:   fmt.Sprintf("%d", cell.Output.Capacity),
				Address: addr,
			})
			tx.Witnesses = append(tx.Witnesses, []byte{})
			balance += cell.Output.Capacity
		}
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	tx.Witnesses[0] = emptyWitness

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 0,
		Lock: &types.Script{
			CodeHash: types.HexToHash(config.ACP.Script.CodeHash),
			HashType: types.ScriptHashType(config.ACP.Script.HashType),
			Args:     parsedAddr.Script.Args,
		},
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})

	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	if err != nil {
		return nil, nil, err
	}

	tx.Outputs[0].Capacity = balance - fee

	return tx, inputs, nil
}

func BuildUdtCellTransaction(addr string, tokenIdentifier string, client rpc.Client, config *config.Config) (*types.Transaction, []btx.Input, error) {
	var uuid string
	for key, token := range config.UDT.Tokens {
		if token.Symbol == tokenIdentifier {
			uuid = key
			break
		}
	}
	if uuid == "" {
		return nil, nil, ErrUnknownToken
	}

	inputs := make([]btx.Input, 0)
	fromParsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, nil, err
	}
	if fromParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return nil, nil, ErrNotAcpLock
	}

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}
	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: types.DepType(config.ACP.Deps[0].DepType),
	}
	tx.CellDeps = append(tx.CellDeps, &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.UDT.Deps[0].TxHash),
			Index:  config.UDT.Deps[0].Index,
		},
		DepType: types.DepType(config.UDT.Deps[0].DepType),
	})

	var total uint64
	searchKey := &indexer.SearchKey{
		Script:     fromParsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}
	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			total = cell.Output.Capacity
			tx.Inputs = append(tx.Inputs, &types.CellInput{
				Since:          0,
				PreviousOutput: cell.OutPoint,
			})
			inputs = append(inputs, btx.Input{
				Value:   fmt.Sprintf("%d", cell.Output.Capacity),
				Address: addr,
			})
			tx.Witnesses = append(tx.Witnesses, []byte{})
			break
		}
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	tx.Witnesses[0] = emptyWitness

	if total < CkbCapacity+UdtCapacity {
		return nil, nil, err
	}
	udtArgs, _ := hex.DecodeString(uuid[2:])
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: UdtCapacity,
		Lock:     fromParsedAddr.Script,
		Type: &types.Script{
			CodeHash: types.HexToHash(config.UDT.Script.CodeHash),
			HashType: types.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	tx.OutputsData = append(tx.OutputsData, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: 0,
		Lock:     fromParsedAddr.Script,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})

	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	if err != nil {
		return nil, nil, err
	}
	tx.Outputs[1].Capacity = total - UdtCapacity - fee

	return tx, inputs, nil
}

func SerializeTransaction(tx *types.Transaction) ([]byte, error) {
	txs, err := orpc.TransactionString(tx)
	if err != nil {
		return nil, err
	}
	return []byte(txs), nil
}

func DeserializeTransaction(tx []byte) (*types.Transaction, error) {
	txs, err := orpc.TransactionFromString(string(tx))
	if err != nil {
		return nil, err
	}
	return txs, nil
}
