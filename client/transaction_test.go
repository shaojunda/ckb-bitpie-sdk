package client

import (
	"github.com/shaojunda/ckb-bitpie-sdk/config"
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
}
