package tx

import "time"

// Dict dict
type Dict struct {
	// TxHash is a base32 encoded identifier for this transaction
	TxHash string `json:"tx_hash,omitempty"`
	// Inputs is a list of accounts that sent money. With Algorand, it is length 1.
	Inputs []Input `json:"inputs"`
	// Outputs is a list of accounts that received money. With Algorand, it is length 1.
	Outputs []Output `json:"outputs"`
	// Extra can contain optional information. It is not populated for now.
	// We could map it to fee, or the notes field, tbd.
	Extra interface{} `json:"extra,omitempty"`
	// TxAt refers to the time at which the transaction entered a tx pool.
	TxAt time.Time `json:"tx_at,omitempty"`

	BlockNo uint64 `json:"block_no,omitempty"`
}

// Input represents an input in a TxDict
type Input struct {
	// a human readable string representing a uint64
	Value string `json:"value"`
	// Address is a human-readable account address
	Address         string `json:"address"`
	TokenCode       string `json:"token_code,omitempty"`
	TokenIdentifier string `json:"token_identifier,omitempty"`
	TokenDecimal    int    `json:"token_decimal,omitempty"`
	// Sn is the index of this input. Always 0, for Algorand
	Sn int `json:"sn"`
}

// Output represents an output in a TxDict
type Output Input
