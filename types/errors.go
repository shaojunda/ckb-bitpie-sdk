package types

import "errors"

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
