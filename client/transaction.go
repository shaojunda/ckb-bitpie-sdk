package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/shaojunda/ckb-bitpie-sdk/builder"
	"math/big"
	"strconv"

	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/nervosnetwork/ckb-sdk-go/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	ckbTypes "github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/nervosnetwork/ckb-sdk-go/utils"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"github.com/shaojunda/ckb-bitpie-sdk/types"
	btx "github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
)

func BuildNormalTransaction(from string, to string, amount string, tokenIdentifier string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
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

func buildCkbTransaction(fromAddr string, toAddr string, from *ckbTypes.Script, to *ckbTypes.Script, amount string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
	var total uint64
	total, _ = strconv.ParseUint(amount, 10, 64)

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}
	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(config.ACP.Deps[0].DepType),
	}

	inputs := make([]btx.Input, 0)
	var toCapacity, fromCapacity uint64

	if to.CodeHash.String() == config.ACP.Script.CodeHash {
		searchKey := &indexer.SearchKey{
			Script:     to,
			ScriptType: indexer.ScriptTypeLock,
		}
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, "")
		if err != nil {
			return nil, nil, err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				toCapacity = cell.Output.Capacity
				tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
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
		if total < types.CkbCapacity {
			return nil, nil, types.ErrNoneAcpCell
		}
		toNormal = true
	}

	searchKey := &indexer.SearchKey{
		Script:     from,
		ScriptType: indexer.ScriptTypeLock,
	}

	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			if cell.Output.Capacity < total+types.CkbCapacity {
				return nil, nil, types.ErrInsufficientCkbBalance
			}
			fromCapacity = cell.Output.Capacity
			tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
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
		return nil, nil, types.ErrInsufficientCkbBalance
	}
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()

	if toNormal {
		tx.Witnesses[0] = emptyWitness
	} else {
		tx.Witnesses[1] = emptyWitness
	}

	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: toCapacity + total,
		Lock:     to,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})
	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: 0,
		Lock:     from,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})
	fee, err := transaction.CalculateTransactionFee(tx, types.FeeRate)
	fee += uint64(len(tx.Witnesses)-1) * 8
	if err != nil {
		return nil, nil, err
	}
	tx.Outputs[1].Capacity = fromCapacity - total - fee

	if tx.Outputs[1].Capacity < types.CkbCapacity {
		return nil, nil, types.ErrInsufficientCkbBalance
	}

	return tx, inputs, nil
}

func buildUdtTransaction(fromAddr string, toAddr string, from *ckbTypes.Script, to *ckbTypes.Script, amount string, tokenIdentifier string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
	err := validateAddresses(fromAddr, toAddr, from, to, config)
	if err != nil {
		return nil, nil, err
	}

	tInfo, err := generateTokenInfo(config, tokenIdentifier)
	if err != nil {
		return nil, nil, err
	}
	transferUdtAmount, ok := big.NewInt(0).SetString(amount, 10)
	if !ok {
		return nil, nil, types.ErrInvalidTransferUdtAmount
	}

	unsignedAcpSudtTxBuilder := builder.NewUnsignedAcpSudtTxBuilder(fromAddr, toAddr, from, to, transferUdtAmount, tInfo, client, config)
	tx, inputs, err := unsignedAcpSudtTxBuilder.Build()
	if err != nil {
		return nil, nil, err
	}

	return tx, inputs, nil
}

func validateAddresses(fromAddr string, toAddr string, from *ckbTypes.Script, to *ckbTypes.Script, config *config.Config) error {
	fromParsedAddr, err := address.Parse(fromAddr)
	if err != nil {
		return err
	}
	if fromParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return types.ErrInvalidFromAddress
	}
	toParsedAddr, err := address.Parse(toAddr)
	if err != nil {
		return err
	}
	if toParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return err
	}
	fromLockHash, err := fromParsedAddr.Script.Hash()
	if err != nil {
		return err
	}
	fromPLockHash, err := from.Hash()
	if err != nil {
		return err
	}
	if fromLockHash != fromPLockHash {
		return types.ErrFromScriptMissMatch
	}
	toLockHash, err := toParsedAddr.Script.Hash()
	if err != nil {
		return err
	}
	toPLockHash, err := to.Hash()
	if err != nil {
		return err
	}
	if toLockHash != toPLockHash {
		return types.ErrToScriptMissMatch
	}
	return nil
}

func generateTokenInfo(config *config.Config, tokenIdentifier string) (tInfo types.TokenInfo, err error) {
	for identifier, token := range config.UDT.Tokens {
		if identifier == tokenIdentifier {
			tInfo = types.TokenInfo{TokenCode: token.Symbol, TokenIdentifier: identifier, TokenDecimal: token.Decimal}
			break
		}
	}
	if tInfo.TokenIdentifier == "" {
		return types.TokenInfo{}, types.ErrUnknownToken
	}
	return
}

func BuildEmptyTransaction(fromAddr string, toAddr string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
	fromParsedAddr, err := address.Parse(fromAddr)
	if err != nil {
		return nil, nil, err
	}
	if fromParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return nil, nil, types.ErrNotAcpLock
	}
	toParsedAddr, err := address.Parse(toAddr)
	if err != nil {
		return nil, nil, err
	}

	inputs := make([]btx.Input, 0)

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}

	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(config.ACP.Deps[0].DepType),
	}
	var toCapacity uint64
	if toParsedAddr.Script.CodeHash.String() == config.ACP.Script.CodeHash {
		toSearchKey := &indexer.SearchKey{
			Script:     toParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		liveCells, err := client.GetCells(context.Background(), toSearchKey, indexer.SearchOrderAsc, types.MaxInput, "")
		if err != nil {
			return nil, nil, err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				toCapacity = cell.Output.Capacity
				tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
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
		if len(tx.Inputs) == 0 {
			return nil, nil, types.ErrNoneAcpCell
		}
	}
	toNormal := false
	if len(tx.Inputs) == 0 {
		toNormal = true
	}

	searchKey := &indexer.SearchKey{
		Script:     fromParsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}
	var cursor string
	var balance uint64
	for {
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, cursor)
		if err != nil {
			return nil, nil, err
		}
		if len(liveCells.Objects) == 0 {
			return nil, nil, types.ErrInsufficientCkbBalance
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})

				inputs = append(inputs, btx.Input{
					Value:   fmt.Sprintf("%d", cell.Output.Capacity),
					Address: fromAddr,
				})
				tx.Witnesses = append(tx.Witnesses, []byte{})
				balance += cell.Output.Capacity
			}
		}
		if len(liveCells.Objects) < int(types.MaxInput) || liveCells.LastCursor == "" {
			break
		}
		cursor = liveCells.LastCursor
	}

	if balance == 0 {
		return nil, nil, types.ErrInsufficientCkbBalance
	}

	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	if toNormal {
		tx.Witnesses[0] = emptyWitness
	} else {
		tx.Witnesses[1] = emptyWitness
	}

	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: 0,
		Lock:     toParsedAddr.Script,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})

	fee, err := transaction.CalculateTransactionFee(tx, types.FeeRate)
	fee += uint64(len(tx.Witnesses)-1) * 8
	if err != nil {
		return nil, nil, err
	}

	tx.Outputs[0].Capacity = balance + toCapacity - fee

	return tx, inputs, nil
}

func BuildTransformAccountTransaction(addr string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
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

	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	if len(liveCells.Objects) == 0 {
		return nil, nil, types.ErrInsufficientCkbBalance
	}

	var balance uint64 = 0
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
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

	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: 0,
		Lock: &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(config.ACP.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(config.ACP.Script.HashType),
			Args:     parsedAddr.Script.Args,
		},
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})
	fee, err := transaction.CalculateTransactionFee(tx, types.FeeRate)
	fee += uint64(len(tx.Witnesses)-1) * 8 + 4
	if err != nil {
		return nil, nil, err
	}

	tx.Outputs[0].Capacity = balance - fee

	return tx, inputs, nil
}

func BuildUdtCellTransaction(addr string, tokenIdentifier string, client rpc.Client, config *config.Config) (*ckbTypes.Transaction, []btx.Input, error) {
	var uuid string
	for key, token := range config.UDT.Tokens {
		if token.Symbol == tokenIdentifier {
			uuid = key
			break
		}
	}
	if uuid == "" {
		return nil, nil, types.ErrUnknownToken
	}

	inputs := make([]btx.Input, 0)
	fromParsedAddr, err := address.Parse(addr)
	if err != nil {
		return nil, nil, err
	}
	if fromParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return nil, nil, types.ErrNotAcpLock
	}

	scripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, nil, err
	}
	tx := transaction.NewSecp256k1SingleSigTx(scripts)
	tx.CellDeps[0] = &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(config.ACP.Deps[0].DepType),
	}
	tx.CellDeps = append(tx.CellDeps, &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(config.UDT.Deps[0].TxHash),
			Index:  config.UDT.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(config.UDT.Deps[0].DepType),
	})

	var total uint64
	searchKey := &indexer.SearchKey{
		Script:     fromParsedAddr.Script,
		ScriptType: indexer.ScriptTypeLock,
	}
	liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, "")
	if err != nil {
		return nil, nil, err
	}
	for _, cell := range liveCells.Objects {
		if cell.Output.Type == nil && len(cell.OutputData) == 0 {
			total = cell.Output.Capacity
			tx.Inputs = append(tx.Inputs, &ckbTypes.CellInput{
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

	if total < types.CkbCapacity+types.UdtCapacity {
		return nil, nil, err
	}
	udtArgs, _ := hex.DecodeString(uuid[2:])
	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: types.UdtCapacity,
		Lock:     fromParsedAddr.Script,
		Type: &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(config.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	tx.OutputsData = append(tx.OutputsData, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	tx.Outputs = append(tx.Outputs, &ckbTypes.CellOutput{
		Capacity: 0,
		Lock:     fromParsedAddr.Script,
	})
	tx.OutputsData = append(tx.OutputsData, []byte{})

	fee, err := transaction.CalculateTransactionFee(tx, types.FeeRate)
	fee += uint64(len(tx.Witnesses)-1) * 8
	if err != nil {
		return nil, nil, err
	}
	tx.Outputs[1].Capacity = total - types.UdtCapacity - fee

	return tx, inputs, nil
}

func SerializeTransaction(tx *ckbTypes.Transaction) ([]byte, error) {
	txs, err := rpc.TransactionString(tx)
	if err != nil {
		return nil, err
	}
	return []byte(txs), nil
}

func DeserializeTransaction(tx []byte) (*ckbTypes.Transaction, error) {
	txs, err := rpc.TransactionFromString(string(tx))
	if err != nil {
		return nil, err
	}
	return txs, nil
}

func Transaction2TxDictOffline(inputs []btx.Input, rawTx *ckbTypes.Transaction, config *config.Config) (result *btx.Dict, err error) {
	result = &btx.Dict{}

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
				result.Outputs = append(result.Outputs, btx.Output{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       token.Symbol,
					TokenIdentifier: uuid,
					TokenDecimal:    token.Decimal,
				})
			} else {
				result.Outputs = append(result.Outputs, btx.Output{
					Value:           amount.String(),
					Address:         addr,
					Sn:              i,
					TokenCode:       "",
					TokenIdentifier: uuid,
					TokenDecimal:    0,
				})
			}
		} else {
			result.Outputs = append(result.Outputs, btx.Output{
				Value:   fmt.Sprintf("%d", output.Capacity),
				Address: addr,
				Sn:      i,
			})
		}
	}

	return
}
