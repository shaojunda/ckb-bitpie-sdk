package builder

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nervosnetwork/ckb-sdk-go/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/rpc"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	ckbTypes "github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"github.com/shaojunda/ckb-bitpie-sdk/types"
	btx "github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
	"math/big"
)

type UnsignedAcpSudtTxBuilder struct {
	fromAddr          string
	toAddr            string
	from              *ckbTypes.Script
	to                *ckbTypes.Script
	config            *config.Config
	client            rpc.Client
	tInfo             types.TokenInfo
	transferUdtAmount *big.Int
}

func (a UnsignedAcpSudtTxBuilder) HandleTxFee(tx *ckbTypes.Transaction, options map[string]interface{}) ([]*ckbTypes.CellInput, []*ckbTypes.CellOutput, [][]byte, [][]byte, []btx.Input, uint64, error) {
	var finalFee uint64
	tmpTx := new(ckbTypes.Transaction)
	if err := deepCopy(tmpTx, tx); err != nil {
		return nil, nil, nil, nil, nil, 0, err
	}
	fee, err := transaction.CalculateTransactionFee(tmpTx, types.FeeRate)
	if err != nil {
		return nil, nil, nil, nil, nil, 0, err
	}
	fee += uint64(len(tmpTx.Witnesses)-1) * 8

	var needCollectInputForFee bool
	var fromAcpCellOriginCapacity uint64
	if _, ok := options["fromAcpCellOriginCapacity"]; ok {
		fromAcpCellOriginCapacity = options["fromAcpCellOriginCapacity"].(uint64)
	} else {
		return nil, nil, nil, nil, nil, 0, errors.New("missing fromAcpCellOriginCapacity")
	}
	var extraCapacity uint64
	if _, ok := options["extraCapacity"]; ok {
		extraCapacity = options["extraCapacity"].(uint64)
	}
	if fromAcpCellOriginCapacity-fee < types.UdtCapacity {
		if extraCapacity > 0 {
			extraOutput := tmpTx.Outputs[len(tmpTx.Outputs)-1]
			extraOutput.Capacity = extraCapacity - fee
		} else {
			needCollectInputForFee = true
		}
	} else {
		tmpTx.Outputs[1].Capacity = fromAcpCellOriginCapacity - fee
		finalFee = fee
	}

	var inputs []btx.Input
	var cellInputs []*ckbTypes.CellInput
	var witnesses [][]byte
	var cellOutputs []*ckbTypes.CellOutput
	var outputsData [][]byte
	if needCollectInputForFee {
		// set change output
		changeOutput := &ckbTypes.CellOutput{
			Capacity: 0,
			Lock:     a.from,
		}
		tmpTx.Outputs = append(tmpTx.Outputs, changeOutput)
		tmpTx.OutputsData = append(tmpTx.OutputsData, []byte{})
		cellOutputs = append(cellOutputs, changeOutput)
		outputsData = append(outputsData, []byte{})
		var cursor string
		searchKey := &indexer.SearchKey{
			Script:     a.from,
			ScriptType: indexer.ScriptTypeLock,
		}
		var hasEnoughCapacity bool
		liveCells, err := a.client.GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, types.MaxInput, cursor)
		if err != nil {
			return nil, nil, nil, nil, nil, 0, err
		}
		for _, cell := range liveCells.Objects {
			if cell.Output.Type == nil && len(cell.OutputData) == 0 {
				cellInputs = append(cellInputs, &ckbTypes.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				tmpTx.Inputs = append(tmpTx.Inputs, &ckbTypes.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				inputs = append(inputs, btx.Input{
					Value:   fmt.Sprintf("%d", cell.Output.Capacity),
					Address: a.fromAddr,
				})
				witnesses = append(witnesses, []byte{})
				tmpTx.Witnesses = append(tmpTx.Witnesses, []byte{})
				fee, err := transaction.CalculateTransactionFee(tmpTx, types.FeeRate)
				if err != nil {
					return nil, nil, nil, nil, nil, 0, err
				}
				fee += uint64(len(tmpTx.Witnesses)-1) * 8
				changeOutput.Capacity = cell.Output.Capacity - fee
				hasEnoughCapacity = true
				break
			}
		}
		if !hasEnoughCapacity {
			return nil, nil, nil, nil, nil, 0, types.ErrInsufficientCkbBalance
		}
	}
	return cellInputs, cellOutputs, witnesses, outputsData, inputs, finalFee, nil
}

func (a UnsignedAcpSudtTxBuilder) Build() (*ckbTypes.Transaction, []btx.Input, error) {
	cellDeps, err := a.BuildCellDeps()
	if err != nil {
		return nil, nil, err
	}
	inputs, btxInputs, options, err := a.BuildInputs()
	if err != nil {
		return nil, nil, err
	}
	outputs, outputOptions, err := a.BuildOutputs(options)
	if err != nil {
		return nil, nil, err
	}
	outputsData, err := a.BuildOutputsData(len(outputs), outputOptions)
	if err != nil {
		return nil, nil, err
	}
	witnesses, err := a.BuildWitnesses(len(inputs))
	if err != nil {
		return nil, nil, err
	}
	tx := &ckbTypes.Transaction{
		Version:     0,
		CellDeps:    cellDeps,
		HeaderDeps:  []ckbTypes.Hash{},
		Inputs:      inputs,
		Outputs:     outputs,
		OutputsData: outputsData,
		Witnesses:   witnesses,
	}
	cellInputs, cellOutputs, newWitnesses, newOutputsData, newBtxInputs, finalFee, err := a.HandleTxFee(tx, options)
	if err != nil {
		return nil, nil, err
	}
	if len(cellInputs) > 0 {
		tx.Inputs = append(tx.Inputs, cellInputs...)
		tx.Outputs = append(tx.Outputs, cellOutputs...)
		tx.Witnesses = append(tx.Witnesses, newWitnesses...)
		tx.OutputsData = append(tx.OutputsData, newOutputsData...)
		btxInputs = append(btxInputs, newBtxInputs...)
	} else {
		var fromAcpCellOriginCapacity uint64
		if _, ok := options["fromAcpCellOriginCapacity"]; ok {
			fromAcpCellOriginCapacity = options["fromAcpCellOriginCapacity"].(uint64)
		}
		tx.Outputs[1].Capacity = fromAcpCellOriginCapacity - finalFee
	}
	return tx, btxInputs, nil
}

func (a UnsignedAcpSudtTxBuilder) BuildCellDeps() ([]*ckbTypes.CellDep, error) {
	var cellDeps []*ckbTypes.CellDep
	// add acp cellDep
	cellDeps = append(cellDeps, &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(a.config.ACP.Deps[0].TxHash),
			Index:  a.config.ACP.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(a.config.ACP.Deps[0].DepType),
	})
	// add sUDT cellDep
	cellDeps = append(cellDeps, &ckbTypes.CellDep{
		OutPoint: &ckbTypes.OutPoint{
			TxHash: ckbTypes.HexToHash(a.config.UDT.Deps[0].TxHash),
			Index:  a.config.UDT.Deps[0].Index,
		},
		DepType: ckbTypes.DepType(a.config.UDT.Deps[0].DepType),
	})

	return cellDeps, nil
}

func (a UnsignedAcpSudtTxBuilder) BuildInputs() ([]*ckbTypes.CellInput, []btx.Input, map[string]interface{}, error) {
	toSearchKey := &indexer.SearchKey{
		Script:     a.to,
		ScriptType: indexer.ScriptTypeLock,
	}
	var cellInputs []*ckbTypes.CellInput
	var btxInputs []btx.Input
	options := make(map[string]interface{})
	// collect toAddr first acp cell
	var toLiveCells *indexer.LiveCells
	toLiveCells, err := a.client.GetCells(context.Background(), toSearchKey, indexer.SearchOrderAsc, types.MaxInput, "")
	if err != nil {
		return nil, nil, nil, err
	}
	for _, cell := range toLiveCells.Objects {
		if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == a.config.UDT.Script.CodeHash {
			args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
			if a.tInfo.TokenIdentifier == args {
				options["toAcpCellOriginCapacity"] = cell.Output.Capacity
				cellInputs = append(cellInputs, &ckbTypes.CellInput{
					Since:          0,
					PreviousOutput: cell.OutPoint,
				})
				options["toAcpCellOriginAmount"] = sudtAmount(cell.OutputData)
				btxInputs = append(btxInputs, btx.Input{
					Value:           options["toAcpCellOriginAmount"].(*big.Int).String(),
					Address:         a.toAddr,
					TokenCode:       a.tInfo.TokenCode,
					TokenIdentifier: a.tInfo.TokenIdentifier,
					TokenDecimal:    a.tInfo.TokenDecimal,
				})
				break
			}
		}
	}
	if len(cellInputs) == 0 {
		return nil, nil, nil, types.ErrToAddrNoneAcpCell
	}

	fromSearchKey := &indexer.SearchKey{
		Script:     a.from,
		ScriptType: indexer.ScriptTypeLock,
	}

	var cursor string
	var hasEnoughUdt bool
	options["collectedFromAcpCellAmount"] = big.NewInt(0)
	var fromLiveCells *indexer.LiveCells
	var collectedFromAcpCellCount int
	// collect fromAddr acp cells
	for {
		fromLiveCells, err = a.client.GetCells(context.Background(), fromSearchKey, indexer.SearchOrderAsc, types.MaxInput, cursor)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, cell := range fromLiveCells.Objects {
			if cell.Output.Type != nil && cell.Output.Type.CodeHash.String() == a.config.UDT.Script.CodeHash {
				args := "0x" + hex.EncodeToString(cell.Output.Type.Args)
				if a.tInfo.TokenIdentifier == args {
					udtAmount := sudtAmount(cell.OutputData)
					options["collectedFromAcpCellAmount"].(*big.Int).Add(options["collectedFromAcpCellAmount"].(*big.Int), udtAmount)
					if collectedFromAcpCellCount == 0 {
						options["fromAcpCellOriginCapacity"] = cell.Output.Capacity
					} else {
						options["extraCapacity"] = options["extraCapacity"].(uint64) + cell.Output.Capacity
					}
					collectedFromAcpCellCount++
					cellInputs = append(cellInputs, &ckbTypes.CellInput{
						Since:          0,
						PreviousOutput: cell.OutPoint,
					})
					btxInputs = append(btxInputs, btx.Input{
						Value:           udtAmount.String(),
						Address:         a.fromAddr,
						TokenCode:       a.tInfo.TokenCode,
						TokenIdentifier: a.tInfo.TokenIdentifier,
						TokenDecimal:    a.tInfo.TokenDecimal,
					})
					if options["collectedFromAcpCellAmount"].(*big.Int).Cmp(a.transferUdtAmount) >= 0 {
						hasEnoughUdt = true
						break
					}
				}
			}
		}
		if hasEnoughUdt || len(fromLiveCells.Objects) < int(types.MaxInput) || fromLiveCells.LastCursor == "" {
			break
		}
		cursor = fromLiveCells.LastCursor
	}

	if !hasEnoughUdt {
		return nil, nil, nil, types.ErrInsufficientSudtBalance
	}
	return cellInputs, btxInputs, options, nil
}

func (a UnsignedAcpSudtTxBuilder) BuildOutputs(options map[string]interface{}) ([]*ckbTypes.CellOutput, map[string]interface{}, error) {
	var cellOutputs []*ckbTypes.CellOutput
	outputOptions := make(map[string]interface{})
	udtArgs, _ := hex.DecodeString(a.tInfo.TokenIdentifier[2:])
	var toAcpCellOriginCapacity uint64
	if _, ok := options["toAcpCellOriginCapacity"]; ok {
		toAcpCellOriginCapacity = options["toAcpCellOriginCapacity"].(uint64)
	} else {
		return nil, nil, errors.New("missing toAcpCellOriginCapacity")
	}
	// set to acp cell to outputs
	cellOutputs = append(cellOutputs, &ckbTypes.CellOutput{
		Capacity: toAcpCellOriginCapacity,
		Lock:     a.to,
		Type: &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(a.config.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(a.config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})
	var toAcpCellOriginAmount *big.Int
	if _, ok := options["toAcpCellOriginAmount"]; ok {
		toAcpCellOriginAmount = options["toAcpCellOriginAmount"].(*big.Int)
	} else {
		return nil, nil, errors.New("missing toAcpCellOriginAmount")
	}

	finalToAcpCellAmount := big.NewInt(0).Add(toAcpCellOriginAmount, a.transferUdtAmount)
	outputOptions["finalToAcpCellAmountBytes"] = generateSudtAmount(finalToAcpCellAmount)
	// set from acp cell to outputs
	var fromAcpCellOriginCapacity uint64
	if _, ok := options["fromAcpCellOriginCapacity"]; ok {
		fromAcpCellOriginCapacity = options["fromAcpCellOriginCapacity"].(uint64)
	} else {
		return nil, nil, errors.New("missing fromAcpCellOriginCapacity")
	}
	cellOutputs = append(cellOutputs, &ckbTypes.CellOutput{
		Capacity: fromAcpCellOriginCapacity,
		Lock:     a.from,
		Type: &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(a.config.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(a.config.UDT.Script.HashType),
			Args:     udtArgs,
		},
	})

	var collectedFromAcpCellAmount *big.Int
	if _, ok := options["collectedFromAcpCellAmount"]; ok {
		collectedFromAcpCellAmount = options["collectedFromAcpCellAmount"].(*big.Int)
	} else {
		return nil, nil, errors.New("missing collectedFromAcpCellAmount")
	}
	finalFromAcpCellAmount := big.NewInt(0).Sub(collectedFromAcpCellAmount, a.transferUdtAmount)
	outputOptions["finalFromAcpCellAmountBytes"] = generateSudtAmount(finalFromAcpCellAmount)
	var extraCapacity uint64
	if _, ok := options["extraCapacity"]; ok {
		extraCapacity = options["extraCapacity"].(uint64)
		if extraCapacity > 0 {
			cellOutputs = append(cellOutputs, &ckbTypes.CellOutput{
				Capacity: extraCapacity,
				Lock:     a.from,
			})
		}
	}

	return cellOutputs, outputOptions, nil
}

func (a UnsignedAcpSudtTxBuilder) BuildOutputsData(cellOutputsSize int, options map[string]interface{}) ([][]byte, error) {
	var outputsData [][]byte
	var finalToAcpCellAmountBytes []byte
	var finalFromAcpCellAmountBytes []byte
	if _, ok := options["finalToAcpCellAmountBytes"]; ok {
		finalToAcpCellAmountBytes = options["finalToAcpCellAmountBytes"].([]byte)
	} else {
		return nil, errors.New("missing finalToAcpCellAmountBytes")
	}
	if _, ok := options["finalFromAcpCellAmountBytes"]; ok {
		finalFromAcpCellAmountBytes = options["finalFromAcpCellAmountBytes"].([]byte)
	} else {
		return nil, errors.New("missing finalFromAcpCellAmountBytes")
	}
	outputsData = append(outputsData, finalToAcpCellAmountBytes, finalFromAcpCellAmountBytes)
	if cellOutputsSize > 2 {
		for i := 2; i < cellOutputsSize; i++ {
			outputsData = append(outputsData, []byte{})
		}
	}
	return outputsData, nil
}

func (a UnsignedAcpSudtTxBuilder) BuildWitnesses(cellInputsSize int) ([][]byte, error) {
	var witnesses [][]byte
	emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
	for i := 0; i < cellInputsSize; i++ {
		if i == 1 {
			witnesses = append(witnesses, emptyWitness)
		} else {
			witnesses = append(witnesses, []byte{})
		}
	}
	return witnesses, nil
}

func sudtAmount(outputData []byte) *big.Int {
	b := outputData[0:16]
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}

	return big.NewInt(0).SetBytes(b)
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

func NewUnsignedAcpSudtTxBuilder(fromAddr string, toAddr string, from *ckbTypes.Script, to *ckbTypes.Script, transferUdtAmount *big.Int, tInfo types.TokenInfo, client rpc.Client, config *config.Config) UnsignedTxBuilder {
	return &UnsignedAcpSudtTxBuilder{
		fromAddr:          fromAddr,
		toAddr:            toAddr,
		from:              from,
		to:                to,
		config:            config,
		client:            client,
		tInfo:             tInfo,
		transferUdtAmount: transferUdtAmount,
	}
}

func deepCopy(dst, src interface{}) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(src); err != nil {
		return err
	}
	return gob.NewDecoder(bytes.NewBuffer(buf.Bytes())).Decode(dst)
}
