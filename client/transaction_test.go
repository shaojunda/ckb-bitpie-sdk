package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/google/go-cmp/cmp"
	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/nervosnetwork/ckb-sdk-go/indexer"
	"github.com/nervosnetwork/ckb-sdk-go/transaction"
	ckbTypes "github.com/nervosnetwork/ckb-sdk-go/types"
	"github.com/nervosnetwork/ckb-sdk-go/utils"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"github.com/shaojunda/ckb-bitpie-sdk/mocks"
	btx "github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
	"math"
	"math/big"
	"testing"
)

func TestBuildNormalTransaction(t *testing.T) {
	addressCases := []struct {
		Name     string
		FromAddr string
		ToAddr   string
		Err      error
	}{
		{"from old acp address", "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu", "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", ErrorNotSupportTransferFromOldAcpAddress},
		{"to old acp address", "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k", "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu", ErrorNotSupportTransferToOldAcpAddress},
	}
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}

	for _, c := range addressCases {
		t.Run(c.Name, func(t *testing.T) {
			if _, _, ans := BuildNormalTransaction(c.FromAddr, c.ToAddr, "1000", "", nil, conf); ans != c.Err {
				t.Fatalf("should return error %v", c.Err)
			}
		})
	}
}

func TestBuildAcpCellsTransferTransaction(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	t.Run("not old acp address", func(t *testing.T) {
		fromAddr := "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k"
		_, _, err = BuildAcpCellsTransferTransaction(fromAddr, nil, conf)
		if err != ErrNotOldAcpAddress {
			t.Errorf("should return error %v", ErrNotOldAcpAddress)
		}
	})

	t.Run("there is no acp cells", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mocks.NewMockClient(ctrl)
		oldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
		oldAcpParsedAddr, err := address.Parse(oldAcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		searchKey := &indexer.SearchKey{
			Script:     oldAcpParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		liveCells := &indexer.LiveCells{
			LastCursor: "",
			Objects:    []*indexer.LiveCell{},
		}
		m.EXPECT().GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, gomock.Any()).Return(liveCells, nil)

		tx, inputs, err := BuildAcpCellsTransferTransaction(oldAcpAddr, m, conf)
		if err != ErrNoneAcpCell {
			t.Fatalf("want %v but got %v", ErrNoneAcpCell, err)
		}
		if tx != nil {
			t.Fatal("tx should be nil")
		}
		if inputs != nil {
			t.Fatal("inputs should be nil")
		}
	})

	t.Run("only one old udt acp cell", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mocks.NewMockClient(ctrl)
		oldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
		oldAcpParsedAddr, err := address.Parse(oldAcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		searchKey := &indexer.SearchKey{
			Script:     oldAcpParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		uuidStr := "0xeb1d5de06feee7fc0566386bd16b5d6141ac4278f1325e3ad7b984f5a9368507"
		uuid, _ := hex.DecodeString(uuidStr[2:])
		udtType := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.UDT.Script.HashType),
			Args:     uuid,
		}
		amountBytes := utils.GenerateSudtAmount(big.NewInt(100000000000))
		newAcpLock := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.ACP.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.ACP.Script.HashType),
			Args:     oldAcpParsedAddr.Script.Args,
		}
		liveCells := &indexer.LiveCells{
			LastCursor: "",
			Objects: []*indexer.LiveCell{{
				BlockNumber: 1000,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x8aa76892d65a1e9964b093e71bdb89b53d65f68d5c001d2199edd6c79db7f7ad"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(145 * math.Pow10(8)),
					Lock:     newAcpLock,
					Type:     udtType,
				},
				OutputData: amountBytes,
				TxIndex:    0,
			}},
		}
		liveCell := liveCells.Objects[0]
		m.EXPECT().GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, gomock.Any()).Return(liveCells, nil)
		expectedTx := &ckbTypes.Transaction{
			Version:    0,
			HeaderDeps: []ckbTypes.Hash{},
			CellDeps: []*ckbTypes.CellDep{
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.ACP.Deps[0].TxHash),
						Index:  conf.ACP.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.ACP.Deps[0].DepType),
				},
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.UDT.Deps[0].TxHash),
						Index:  conf.UDT.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.UDT.Deps[0].DepType),
				},
			},
		}
		expectedTx.Inputs = append(expectedTx.Inputs, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: liveCell.OutPoint,
		})
		expectedInputs := make([]btx.Input, 0)
		amount, _ := utils.ParseSudtAmount(liveCell.OutputData)
		token := conf.UDT.Tokens[uuidStr]
		expectedInputs = append(expectedInputs, btx.Input{
			Value:           amount.String(),
			Address:         oldAcpAddr,
			TokenCode:       token.Symbol,
			TokenIdentifier: uuidStr,
			TokenDecimal:    token.Decimal,
		})
		emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
		expectedTx.Witnesses = append(expectedTx.Witnesses, emptyWitness)
		expectedTx.Outputs = append(expectedTx.Outputs, &ckbTypes.CellOutput{
			Capacity: liveCell.Output.Capacity,
			Lock:     liveCell.Output.Lock,
			Type:     liveCell.Output.Type,
		})
		expectedTx.OutputsData = append(expectedTx.OutputsData, liveCell.OutputData)
		fee, err := transaction.CalculateTransactionFee(expectedTx, FeeRate)
		if err != nil {
			t.Fatal(err)
		}
		expectedTx.Outputs[0].Capacity = expectedTx.Outputs[0].Capacity - fee
		tx, inputs, err := BuildAcpCellsTransferTransaction(oldAcpAddr, m, conf)
		if !compareTransaction(expectedTx, tx) {
			t.Fatalf("want %+v but got %+v", expectedTx, tx)
		}
		if !compareInputs(expectedInputs, inputs) {
			t.Fatalf("want %+v but got %+v", expectedInputs, inputs)
		}
	})

	t.Run("only one old ckb acp cell", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mocks.NewMockClient(ctrl)
		oldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
		oldAcpParsedAddr, err := address.Parse(oldAcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		searchKey := &indexer.SearchKey{
			Script:     oldAcpParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		newAcpLock := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.ACP.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.ACP.Script.HashType),
			Args:     oldAcpParsedAddr.Script.Args,
		}
		liveCells := &indexer.LiveCells{
			LastCursor: "",
			Objects: []*indexer.LiveCell{{
				BlockNumber: 1000,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x8aa76892d65a1e9964b093e71bdb89b53d65f68d5c001d2199edd6c79db7f7ad"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(145 * math.Pow10(8)),
					Lock:     newAcpLock,
				},
				OutputData: []byte{},
				TxIndex:    0,
			}},
		}
		liveCell := liveCells.Objects[0]
		m.EXPECT().GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, gomock.Any()).Return(liveCells, nil)
		expectedTx := &ckbTypes.Transaction{
			Version:    0,
			HeaderDeps: []ckbTypes.Hash{},
			CellDeps: []*ckbTypes.CellDep{
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.ACP.Deps[0].TxHash),
						Index:  conf.ACP.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.ACP.Deps[0].DepType),
				},
			},
		}
		expectedTx.Inputs = append(expectedTx.Inputs, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: liveCell.OutPoint,
		})
		expectedInputs := make([]btx.Input, 0)
		expectedInputs = append(expectedInputs, btx.Input{
			Value:   fmt.Sprintf("%d", liveCell.Output.Capacity),
			Address: oldAcpAddr,
		})
		emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
		expectedTx.Witnesses = append(expectedTx.Witnesses, emptyWitness)
		expectedTx.Outputs = append(expectedTx.Outputs, &ckbTypes.CellOutput{
			Capacity: liveCell.Output.Capacity,
			Lock:     liveCell.Output.Lock,
			Type:     liveCell.Output.Type,
		})
		expectedTx.OutputsData = append(expectedTx.OutputsData, liveCell.OutputData)
		fee, err := transaction.CalculateTransactionFee(expectedTx, FeeRate)
		if err != nil {
			t.Fatal(err)
		}
		expectedTx.Outputs[0].Capacity = expectedTx.Outputs[0].Capacity - fee
		tx, inputs, err := BuildAcpCellsTransferTransaction(oldAcpAddr, m, conf)
		if !compareTransaction(expectedTx, tx) {
			t.Fatalf("want %+v but got %+v", expectedTx, tx)
		}
		if !compareInputs(expectedInputs, inputs) {
			t.Fatalf("want %+v but got %+v", expectedInputs, inputs)
		}
	})

	t.Run("one old udt acp cell and one old ckb acp cell", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mocks.NewMockClient(ctrl)
		oldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
		oldAcpParsedAddr, err := address.Parse(oldAcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		searchKey := &indexer.SearchKey{
			Script:     oldAcpParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		uuidStr := "0xeb1d5de06feee7fc0566386bd16b5d6141ac4278f1325e3ad7b984f5a9368507"
		uuid, _ := hex.DecodeString(uuidStr[2:])
		udtType := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.UDT.Script.HashType),
			Args:     uuid,
		}
		amountBytes := utils.GenerateSudtAmount(big.NewInt(100000000000))
		newAcpLock := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.ACP.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.ACP.Script.HashType),
			Args:     oldAcpParsedAddr.Script.Args,
		}
		liveCells := &indexer.LiveCells{
			LastCursor: "",
			Objects: []*indexer.LiveCell{{
				BlockNumber: 1000,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x8aa76892d65a1e9964b093e71bdb89b53d65f68d5c001d2199edd6c79db7f7ad"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(145 * math.Pow10(8)),
					Lock:     newAcpLock,
					Type:     udtType,
				},
				OutputData: amountBytes,
				TxIndex:    0,
			}, {
				BlockNumber: 1001,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x7d0ecdb8bad4064788b67dfafe71757e7caa2ad2cbe5597a02df95f8792bdb21"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(1000 * math.Pow10(8)),
					Lock:     newAcpLock,
				},
				OutputData: []byte{},
				TxIndex:    0,
			}},
		}
		sudtLiveCell := liveCells.Objects[0]
		ckbLiveCell := liveCells.Objects[1]
		m.EXPECT().GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, gomock.Any()).Return(liveCells, nil)
		expectedTx := &ckbTypes.Transaction{
			Version:    0,
			HeaderDeps: []ckbTypes.Hash{},
			CellDeps: []*ckbTypes.CellDep{
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.ACP.Deps[0].TxHash),
						Index:  conf.ACP.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.ACP.Deps[0].DepType),
				},
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.UDT.Deps[0].TxHash),
						Index:  conf.UDT.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.UDT.Deps[0].DepType),
				},
			},
		}
		expectedTx.Inputs = append(expectedTx.Inputs, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: sudtLiveCell.OutPoint,
		}, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: ckbLiveCell.OutPoint,
		})
		expectedInputs := make([]btx.Input, 0)
		amount, _ := utils.ParseSudtAmount(sudtLiveCell.OutputData)
		token := conf.UDT.Tokens[uuidStr]
		expectedInputs = append(expectedInputs, btx.Input{
			Value:           amount.String(),
			Address:         oldAcpAddr,
			TokenCode:       token.Symbol,
			TokenIdentifier: uuidStr,
			TokenDecimal:    token.Decimal,
		}, btx.Input{
			Value:   fmt.Sprintf("%d", ckbLiveCell.Output.Capacity),
			Address: oldAcpAddr,
		})
		emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
		expectedTx.Witnesses = append(expectedTx.Witnesses, emptyWitness)
		expectedTx.Witnesses = append(expectedTx.Witnesses, []byte{})
		expectedTx.Outputs = append(expectedTx.Outputs, &ckbTypes.CellOutput{
			Capacity: sudtLiveCell.Output.Capacity,
			Lock:     sudtLiveCell.Output.Lock,
			Type:     sudtLiveCell.Output.Type,
		}, &ckbTypes.CellOutput{
			Capacity: ckbLiveCell.Output.Capacity,
			Lock:     ckbLiveCell.Output.Lock,
		})
		expectedTx.OutputsData = append(expectedTx.OutputsData, sudtLiveCell.OutputData, ckbLiveCell.OutputData)
		fee, err := transaction.CalculateTransactionFee(expectedTx, FeeRate)
		if err != nil {
			t.Fatal(err)
		}
		expectedTx.Outputs[0].Capacity = expectedTx.Outputs[0].Capacity - fee
		tx, inputs, err := BuildAcpCellsTransferTransaction(oldAcpAddr, m, conf)
		if !compareTransaction(expectedTx, tx) {
			t.Fatalf("want %+v but got %+v", expectedTx, tx)
		}
		if !compareInputs(expectedInputs, inputs) {
			t.Fatalf("want %+v but got %+v", expectedInputs, inputs)
		}
	})

	t.Run("one old udt acp cell and two old ckb acp cell", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		m := mocks.NewMockClient(ctrl)
		oldAcpAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
		oldAcpParsedAddr, err := address.Parse(oldAcpAddr)
		if err != nil {
			t.Fatal(err)
		}
		searchKey := &indexer.SearchKey{
			Script:     oldAcpParsedAddr.Script,
			ScriptType: indexer.ScriptTypeLock,
		}
		uuidStr := "0xeb1d5de06feee7fc0566386bd16b5d6141ac4278f1325e3ad7b984f5a9368507"
		uuid, _ := hex.DecodeString(uuidStr[2:])
		udtType := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.UDT.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.UDT.Script.HashType),
			Args:     uuid,
		}
		amountBytes := utils.GenerateSudtAmount(big.NewInt(100000000000))
		newAcpLock := &ckbTypes.Script{
			CodeHash: ckbTypes.HexToHash(conf.ACP.Script.CodeHash),
			HashType: ckbTypes.ScriptHashType(conf.ACP.Script.HashType),
			Args:     oldAcpParsedAddr.Script.Args,
		}
		liveCells := &indexer.LiveCells{
			LastCursor: "",
			Objects: []*indexer.LiveCell{{
				BlockNumber: 1000,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x8aa76892d65a1e9964b093e71bdb89b53d65f68d5c001d2199edd6c79db7f7ad"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(145 * math.Pow10(8)),
					Lock:     newAcpLock,
					Type:     udtType,
				},
				OutputData: amountBytes,
				TxIndex:    0,
			}, {
				BlockNumber: 1001,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x7d0ecdb8bad4064788b67dfafe71757e7caa2ad2cbe5597a02df95f8792bdb21"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(1000 * math.Pow10(8)),
					Lock:     newAcpLock,
				},
				TxIndex: 0,
			}, {
				BlockNumber: 1002,
				OutPoint: &ckbTypes.OutPoint{
					TxHash: ckbTypes.HexToHash("0x05b946b8dd94460f0e33fdc6a0bb210c67eee3e650ba352f7917cfd449b6cfa9"),
					Index:  0,
				},
				Output: &ckbTypes.CellOutput{
					Capacity: uint64(2000 * math.Pow10(8)),
					Lock:     newAcpLock,
				},
				TxIndex: 0,
			}},
		}
		sudtLiveCell := liveCells.Objects[0]
		ckbLiveCell := liveCells.Objects[1]
		ckbLiveCell1 := liveCells.Objects[2]
		m.EXPECT().GetCells(context.Background(), searchKey, indexer.SearchOrderAsc, MaxInput, gomock.Any()).Return(liveCells, nil)
		expectedTx := &ckbTypes.Transaction{
			Version:    0,
			HeaderDeps: []ckbTypes.Hash{},
			CellDeps: []*ckbTypes.CellDep{
				{
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.ACP.Deps[0].TxHash),
						Index:  conf.ACP.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.ACP.Deps[0].DepType),
				}, {
					OutPoint: &ckbTypes.OutPoint{
						TxHash: ckbTypes.HexToHash(conf.UDT.Deps[0].TxHash),
						Index:  conf.UDT.Deps[0].Index,
					},
					DepType: ckbTypes.DepType(conf.UDT.Deps[0].DepType),
				},
			},
		}
		expectedTx.Inputs = append(expectedTx.Inputs, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: sudtLiveCell.OutPoint,
		}, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: ckbLiveCell.OutPoint,
		}, &ckbTypes.CellInput{
			Since:          0,
			PreviousOutput: ckbLiveCell1.OutPoint,
		})
		expectedInputs := make([]btx.Input, 0)
		amount, _ := utils.ParseSudtAmount(sudtLiveCell.OutputData)
		token := conf.UDT.Tokens[uuidStr]
		expectedInputs = append(expectedInputs, btx.Input{
			Value:           amount.String(),
			Address:         oldAcpAddr,
			TokenCode:       token.Symbol,
			TokenIdentifier: uuidStr,
			TokenDecimal:    token.Decimal,
		}, btx.Input{
			Value:   fmt.Sprintf("%d", ckbLiveCell.Output.Capacity),
			Address: oldAcpAddr,
		}, btx.Input{
			Value:   fmt.Sprintf("%d", ckbLiveCell1.Output.Capacity),
			Address: oldAcpAddr,
		})
		emptyWitness, _ := transaction.EmptyWitnessArg.Serialize()
		expectedTx.Witnesses = append(expectedTx.Witnesses, emptyWitness)
		expectedTx.Witnesses = append(expectedTx.Witnesses, []byte{})
		expectedTx.Witnesses = append(expectedTx.Witnesses, []byte{})
		expectedTx.Outputs = append(expectedTx.Outputs, &ckbTypes.CellOutput{
			Capacity: sudtLiveCell.Output.Capacity,
			Lock:     sudtLiveCell.Output.Lock,
			Type:     sudtLiveCell.Output.Type,
		}, &ckbTypes.CellOutput{
			Capacity: ckbLiveCell.Output.Capacity,
			Lock:     ckbLiveCell.Output.Lock,
		}, &ckbTypes.CellOutput{
			Capacity: ckbLiveCell1.Output.Capacity,
			Lock:     ckbLiveCell1.Output.Lock,
		})
		expectedTx.OutputsData = append(expectedTx.OutputsData, sudtLiveCell.OutputData, []byte{}, []byte{})
		fee, err := transaction.CalculateTransactionFee(expectedTx, FeeRate)
		if err != nil {
			t.Fatal(err)
		}
		expectedTx.Outputs[0].Capacity = expectedTx.Outputs[0].Capacity - fee
		tx, inputs, err := BuildAcpCellsTransferTransaction(oldAcpAddr, m, conf)
		if !compareTransaction(expectedTx, tx) {
			t.Fatalf("want %+v but got %+v", expectedTx, tx)
		}
		if !compareInputs(expectedInputs, inputs) {
			t.Fatalf("want %+v but got %+v", expectedInputs, inputs)
		}
	})
}

func compareTransaction(expectedTx, actualTx *ckbTypes.Transaction) bool {
	return cmp.Equal(expectedTx, actualTx)
}

func compareInputs(expectedInputs, actualInputs []btx.Input) bool {
	return cmp.Equal(expectedInputs, actualInputs)
}
