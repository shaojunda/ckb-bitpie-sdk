package builder

import (
	"github.com/nervosnetwork/ckb-sdk-go/types"
	btx "github.com/shaojunda/ckb-bitpie-sdk/utils/tx"
)

type UnsignedTxBuilder interface {
	BuildCellDeps() ([]*types.CellDep, error)
	BuildInputs() ([]*types.CellInput, []btx.Input, map[string]interface{}, error)
	BuildOutputs(options map[string]interface{}) ([]*types.CellOutput, map[string]interface{}, error)
	BuildOutputsData(cellOutputsSize int, options map[string]interface{}) ([][]byte, error)
	BuildWitnesses(cellInputsSize int) ([][]byte, error)
	HandleTxFee(tx *types.Transaction, options map[string]interface{}) ([]*types.CellInput, []*types.CellOutput, [][]byte, [][]byte, []btx.Input, uint64, error)
	Build() (*types.Transaction, []btx.Input, error)
}
