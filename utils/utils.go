package utils

import (
	"github.com/nervosnetwork/ckb-sdk-go/address"
	"github.com/shaojunda/ckb-bitpie-sdk/config"
)

func IsAcpAddress(addr string, config *config.Config) (bool, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return false, err
	}

	if parsedAddr.Script.CodeHash.String() == config.ACP.Script.CodeHash && string(parsedAddr.Script.HashType) == config.ACP.Script.HashType {
		return true, nil
	}

	return false, nil
}

func IsOldAcpAddress(addr string, config *config.Config) (bool, error) {
	parsedAddr, err := address.Parse(addr)
	if err != nil {
		return false, err
	}

	if parsedAddr.Script.CodeHash.String() == config.OldACP.Script.CodeHash && string(parsedAddr.Script.HashType) == config.OldACP.Script.HashType {
		return true, nil
	}

	return false, nil
}
