package client

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/nervosnetwork/ckb-sdk-go/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	"github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/nervosnetwork/ckb-sdk-go/utils"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	btx "github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
)

const (
	MaxInput    uint64 = 1000
	FeeRate     uint64 = 1000
	CkbCapacity uint64 = 6100000000
	UdtCapacity uint64 = 14200000000
)

var (
	ErrInsufficientCkbBalance   = errors.New("insufficient CKB balance")
	ErrInsufficientSudtBalance  = errors.New("insufficient sUDT balance")
	ErrNotAcpLock               = errors.New("address must acp address")
	ErrUnknownToken             = errors.New("unknown token")
	ErrNoneAcpCell              = errors.New("none acy cell")
	ErrToAddrNoneAcpCell        = errors.New("toAddr none acy cell")
	ErrInvalidTransferUdtAmount = errors.New("amount is invalid")
	ErrInvalidFromAddress       = errors.New("from address must be a acp address")
	ErrInvalidToAddress         = errors.New("to address must be a acp address")
	ErrFromScriptMissMatch      = errors.New("fromAddr does not math from script")
	ErrToScriptMissMatch        = errors.New("toAddr does not math to script")
)

type tokenInfo struct {
	TokenCode       string
	TokenIdentifier string
	TokenDecimal    int
}

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
	fee += 8
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
		return nil, nil, ErrInvalidTransferUdtAmount
	}

	inputs := make([]btx.Input, 0)

	tx := &types.Transaction{
		Version:    0,
		HeaderDeps: []types.Hash{},
		CellDeps:   []*types.CellDep{},
	}
	buildCellDeps(tx, config)
	toAcpCellOriginAmount, toAcpCellOriginCapacity, collectedFromAcpCellAmount, fromAcpCellOriginCapacity, extraCapacity, err := buildInputs(fromAddr, toAddr, from, to, client, config, tInfo, tx, inputs, transferUdtAmount)
	if err != nil {
		return nil, nil, err
	}
	finalToAcpCellAmountBytes, finalFromAcpCellAmountBytes := buildOutputs(tInfo, tx, from, to, config, toAcpCellOriginCapacity, toAcpCellOriginAmount, transferUdtAmount, fromAcpCellOriginCapacity, collectedFromAcpCellAmount, extraCapacity)
	buildOutputsData(tx, finalToAcpCellAmountBytes, finalFromAcpCellAmountBytes)
	buildWitnesses(tx)
	err = handleTxFee(tx, client, inputs, fromAddr, from, fromAcpCellOriginCapacity, extraCapacity)
	if err != nil {
		return nil, nil, err
	}

	return tx, inputs, nil
}

func handleTxFee(tx *types.Transaction, client rpc.Client, inputs []btx.Input, fromAddr string, from *types.Script, fromAcpCellOriginCapacity uint64, extraCapacity uint64) error {
	fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
	if err != nil {
		return err
	}
	fee += uint64(len(tx.Witnesses)-1) * 8

	var needCollectInputForFee bool
	if fromAcpCellOriginCapacity-fee < UdtCapacity {
		if extraCapacity > 0 {
			extraOutput := tx.Outputs[len(tx.Outputs)-1]
			extraOutput.Capacity = extraCapacity - fee
		} else {
			needCollectInputForFee = true
		}
	} else {
		tx.Outputs[1].Capacity = fromAcpCellOriginCapacity - fee
	}

	if needCollectInputForFee {
		// set change output
		changeOutput := &types.CellOutput{
			Capacity: 0,
			Lock:     from,
		}
		tx.Outputs = append(tx.Outputs, changeOutput)
		tx.OutputsData = append(tx.OutputsData, []byte{})
		var cursor string
		searchKey := &indexer.SearchKey{
			Script:     from,
			ScriptType: indexer.ScriptTypeLock,
		}
		var hasEnoughCapacity bool
		liveCells, err := client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, cursor)
		if err != nil {
			return err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				tx.Inputs = append(tx.Inputs, &types.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				inputs = append(inputs, btx.Input{
					Value:   fmt.Sprintf("%d", cell.Output.Capacity),
					Address: fromAddr,
				})
				tx.Witnesses = append(tx.Witnesses, []byte{})
				fee, err := transaction.CalculateTransactionFee(tx, FeeRate)
				if err != nil {
					return err
				}
				fee += uint64(len(tx.Witnesses)-1) * 8
				changeOutput.Capacity = cell.Output.Capacity - fee
				hasEnoughCapacity = true
				break
			}
		}
		if !hasEnoughCapacity {
			return ErrInsufficientCkbBalance
		}
	}
	return nil
}

func buildWitnesses(tx *types.Transaction) {
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	for i := 0; i < len(tx.Inputs); i++ {
		if i == 1 {
			tx.Witnesses = append(tx.Witnesses, emptyWitness)
		} else {
			tx.Witnesses = append(tx.Witnesses, []byte{})
		}
	}
}

func buildOutputsData(tx *types.Transaction, finalToAcpCellAmountBytes []byte, finalFromAcpCellAmountBytes []byte) {
	tx.OutputsData = append(tx.OutputsData, finalToAcpCellAmountBytes, finalFromAcpCellAmountBytes)
	if len(tx.Outputs) > 2 {
		for i := 2; i < len(tx.Outputs); i++ {
			tx.OutputsData = append(tx.OutputsData, []byte{})
		}
	}
}

func buildOutputs(tInfo tokenInfo, tx *types.Transaction, from *types.Script, to *types.Script, config *config.Config, toAcpCellOriginCapacity uint64, toAcpCellOriginAmount *big.Int, transferUdtAmount *big.Int, fromAcpCellOriginCapacity uint64, collectedFromAcpCellAmount *big.Int, extraCapacity uint64) (finalToAcpCellAmountBytes []byte, finalFromAcpCellAmountBytes []byte) {
	udtArgs, _ := hex.DecodeString(tInfo.TokenIdentifier[2:])
	// set to acp cell to outputs
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: toAcpCellOriginCapacity,
		Lock:     to,
		Type: &types.Script{
			CodeHash: types.HexToHash(config.UDT.Script.CodeHash),
			HashType: types.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	fmt.Println(toAcpCellOriginAmount.String())
	fmt.Println(collectedFromAcpCellAmount.String())
	finalToAcpCellAmount := big.NewInt(0).Add(toAcpCellOriginAmount, transferUdtAmount)
	finalToAcpCellAmountBytes = generateSudtAmount(finalToAcpCellAmount)
	// set from acp cell to outputs
	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: fromAcpCellOriginCapacity,
		Lock:     from,
		Type: &types.Script{
			CodeHash: types.HexToHash(config.UDT.Script.CodeHash),
			HashType: types.ScriptHashType(config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})

	finalFromAcpCellAmount := big.NewInt(0).Sub(collectedFromAcpCellAmount, transferUdtAmount)
	finalFromAcpCellAmountBytes = generateSudtAmount(finalFromAcpCellAmount)
	fmt.Println(finalFromAcpCellAmount.String())

	if extraCapacity > 0 {
		tx.Outputs = append(tx.Outputs, &types.CellOutput{
			Capacity: extraCapacity,
			Lock:     from,
		})
	}
	return
}

func generateSudtAmount(finalToAcpCellAmount *big.Int) []byte {
	b := finalToAcpCellAmount.Bytes()
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	if len(b) < 16 {
		for i := len(b); i < 16; i++ {
			b = append(b, 0)
		}
	}
	return b
}

func buildInputs(fromAddr string, toAddr string, from *types.Script, to *types.Script, client rpc.Client, config *config.Config, tInfo tokenInfo, tx *types.Transaction, inputs []btx.Input, transferUdtAmount *big.Int) (toAcpCellOriginAmount *big.Int, toAcpCellOriginCapacity uint64, collectedFromAcpCellAmount *big.Int, fromAcpCellOriginCapacity uint64, extraCapacity uint64, err error) {
	toSearchKey := &indexer.SearchKey{
		Script:     to,
		ScriptType: indexer.ScriptTypeLock,
	}
	// collect toAddr first acp cell
	var toLiveCells *indexer.LiveCells
	toLiveCells, err = client.GetCells(context.Background(), toSearchKey, indexer.SearchOrderAsc, MaxInput, "")
	if err != nil {
		return
	}
	for _, cell := range toLiveCells.Objects {
		if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
			args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
			if tInfo.TokenIdentifier == args {
				toAcpCellOriginCapacity = cell.Output.Capacity
				tx.Inputs = append(tx.Inputs, &types.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				toAcpCellOriginAmount = sudtAmount(cell.OutputData)
				inputs = append(inputs, btx.Input{
					Value:           toAcpCellOriginAmount.String(),
					Address:         toAddr,
					TokenCode:       tInfo.TokenCode,
					TokenIdentifier: tInfo.TokenIdentifier,
					TokenDecimal:    tInfo.TokenDecimal,
				})
				break
			}
		}
	}
	if len(tx.Inputs) == 0 {
		err = ErrToAddrNoneAcpCell
		return
	}

	fromSearchKey := &indexer.SearchKey{
		Script:     from,
		ScriptType: indexer.ScriptTypeLock,
	}

	var cursor string
	var hasEnoughUdt bool
	collectedFromAcpCellAmount = big.NewInt(0)
	var fromLiveCells *indexer.LiveCells
	var collectedFromAcpCellCount int
	// collect fromAddr acp cells
	for {
		fromLiveCells, err = client.GetCells(context.Background(), fromSearchKey, indexer.SearchOrderAsc, MaxInput, cursor)
		if err != nil {
			return
		}
		for _, cell := range fromLiveCells.Objects {
			if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == config.UDT.Script.CodeHash {
				args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
				if tInfo.TokenIdentifier == args {
					udtAmount := sudtAmount(cell.OutputData)
					collectedFromAcpCellAmount.Add(collectedFromAcpCellAmount, udtAmount)
					if collectedFromAcpCellCount == 0 {
						fromAcpCellOriginCapacity = cell.Output.Capacity
					} else {
						extraCapacity += cell.Output.Capacity
					}
					collectedFromAcpCellCount++
					tx.Inputs = append(tx.Inputs, &types.CellInput{
						Since:          0,
						PreviousOutput: cell.OutPoint,
					})
					inputs = append(inputs, btx.Input{
						Value:           udtAmount.String(),
						Address:         fromAddr,
						TokenCode:       tInfo.TokenCode,
						TokenIdentifier: tInfo.TokenIdentifier,
						TokenDecimal:    tInfo.TokenDecimal,
					})
					if collectedFromAcpCellAmount.Cmp(transferUdtAmount) >= 0 {
						hasEnoughUdt = true
						break
					}
				}
			}
		}
		if hasEnoughUdt || len(fromLiveCells.Objects) < 1000 || fromLiveCells.LastCursor == "" {
			break
		}
		cursor = fromLiveCells.LastCursor
	}

	if !hasEnoughUdt {
		err = ErrInsufficientSudtBalance
		return
	}
	return
}

func sudtAmount(outputData []byte) *big.Int {
	b := outputData[0:16]
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}

	return big.NewInt(0).SetBytes(b)
}

func validateAddresses(fromAddr string, toAddr string, from *types.Script, to *types.Script, config *config.Config) error {
	fromParsedAddr, err := address.Parse(fromAddr)
	if err != nil {
		return err
	}
	if fromParsedAddr.Script.CodeHash.String() != config.ACP.Script.CodeHash {
		return ErrInvalidFromAddress
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
		return ErrFromScriptMissMatch
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
		return ErrToScriptMissMatch
	}
	return nil
}

func buildCellDeps(tx *types.Transaction, config *config.Config) {
	// add acp cellDep
	tx.CellDeps = append(tx.CellDeps, &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.ACP.Deps[0].TxHash),
			Index:  config.ACP.Deps[0].Index,
		},
		DepType: types.DepType(config.ACP.Deps[0].DepType),
	})
	// add sUDT cellDep
	tx.CellDeps = append(tx.CellDeps, &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash(config.UDT.Deps[0].TxHash),
			Index:  config.UDT.Deps[0].Index,
		},
		DepType: types.DepType(config.UDT.Deps[0].DepType),
	})
}

func generateTokenInfo(config *config.Config, tokenIdentifier string) (tInfo tokenInfo, err error) {
	for identifier, token := range config.UDT.Tokens {
		if identifier == tokenIdentifier {
			tInfo = tokenInfo{TokenCode: token.Symbol, TokenIdentifier: identifier, TokenDecimal: token.Decimal}
			break
		}
	}
	if tInfo.TokenIdentifier == "" {
		return tokenInfo{}, ErrUnknownToken
	}
	return
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
	fee += 8
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
	fee += 8
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
	fee += 8
	if err != nil {
		return nil, nil, err
	}
	tx.Outputs[1].Capacity = total - UdtCapacity - fee

	return tx, inputs, nil
}

func SerializeTransaction(tx *types.Transaction) ([]byte, error) {
	txs, err := rpc.TransactionString(tx)
	if err != nil {
		return nil, err
	}
	return []byte(txs), nil
}

func DeserializeTransaction(tx []byte) (*types.Transaction, error) {
	txs, err := rpc.TransactionFromString(string(tx))
	if err != nil {
		return nil, err
	}
	return txs, nil
}

func Transaction2TxDictOffline(inputs []btx.Input, rawTx *types.Transaction, config *config.Config) (result *btx.Dict, err error) {
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
