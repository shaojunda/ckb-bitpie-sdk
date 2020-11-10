package client

import (
	"github.com/shaojunda/ckb-bitpie-sdk/config"
	"testing"
)

func TestIsOldAcpAddressForOldAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	addr := "ckt1qjr2r35c0f9vhcdgslx2fjwa9tylevr5qka7mfgmscd33wlhfykyhazydxllj3dzvalznz08fs6dugc5mwkhxgdnkqu"
	result, err := IsOldAcpAddress(addr, conf)
	if err != nil {
		t.Error(err)
	}
	if !result {
		t.Errorf("IsOldAcpAddress(%s) = %t; want %t", addr, result, true)
	}
}

func TestIsOldAcpAddressForAcpAddress(t *testing.T) {
	conf, err := config.Load("../config-example.yaml")
	addr := "ckt1qg8mxsu48mncexvxkzgaa7mz2g25uza4zpz062relhjmyuc52ps3razydxllj3dzvalznz08fs6dugc5mwkhxqlfuww"
	result, err := IsOldAcpAddress(addr, conf)
	if err != nil {
		t.Error(err)
	}
	if result {
		t.Errorf("IsOldAcpAddress(%s) = %t; want %t", addr, result, false)
	}
}
