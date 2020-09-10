package client

import "github.com/ququzone/ckb-bitpie-sdk/utils/tx"

type Balance struct {
	TokenCode       string `json:"token_code,omitempty"`
	TokenIdentifier string `json:"token_identifier,omitempty"`
	TokenDecimal    int    `json:"token_decimal,omitempty"`
	Balance         string `json:"balance"`
}

type AddressTxs struct {
	Txs    []*tx.Dict `json:"txs"`
	Cursor string     `json:"cursor"`
}
