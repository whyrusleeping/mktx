package mktx

import (
	"fmt"
	b58 "github.com/jbenet/go-base58"
)

const (
	OP_RETURN = 0x6a

	OP_DUP = 0x76

	OP_EQUALVERIFY = 0x88

	OP_CHECKSIG = 0xac
	OP_HASH160  = 0xa9
)

func OpReturnScript(val []byte) []byte {
	return append([]byte{OP_RETURN, byte(len(val))}, val...)
}

func PayToPubkeyScript(addr string) []byte {
	// OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
	pkval := b58.Decode(addr)
	pkval = pkval[1 : len(pkval)-4]
	if addr[0] == 't' {
		pkval = pkval[1:]
	}
	fmt.Printf("%s = %x\n", addr, pkval)
	return append(append([]byte{OP_DUP, OP_HASH160, byte(len(pkval))}, pkval...), OP_EQUALVERIFY, OP_CHECKSIG)
}
