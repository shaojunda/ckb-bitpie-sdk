package client

import (
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"testing"
)

func TestErrorNotSupportTransferFromOldAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	fromAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
	toAddr := "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k"
	_, _, err = BuildNormalTransaction(fromAddr, toAddr, "1000", "", nil, conf)
	if err != ErrorNotSupportTransferFromOldAcpAddress {
		t.Errorf("should return error %v", err)
	}
}

func TestErrorNotSupportTransferToOldAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	fromAddr := "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k"
	toAddr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
	_, _, err = BuildNormalTransaction(fromAddr, toAddr, "1000", "", nil, conf)
	if err != ErrorNotSupportTransferToOldAcpAddress {
		t.Errorf("should return error %v", err)
	}
}

func TestErrNotOldAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	if err != nil {
		t.Error(err)
	}
	fromAddr := "ckt1qyqt705jmfy3r7jlvg88k87j0sksmhgduazq7x5l8k"
	_, _, err = BuildAcpCellsTransferTransaction(fromAddr, nil, conf)
	if err != ErrNotOldAcpAddress {
		t.Errorf("should return error %v", ErrNotOldAcpAddress)
	}
}
