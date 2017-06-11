package mktx

import (
	"bytes"
	b58 "github.com/jbenet/go-base58"
)

const (
	OP_RETURN = 0x6a

	OP_DUP = 0x76

	OP_EQUAL       = 0x87
	OP_EQUALVERIFY = 0x88

	OP_CHECKSIG = 0xac
	OP_HASH160  = 0xa9

	OP_CHECKMULTISIG = 0xae
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
	return append(append([]byte{OP_DUP, OP_HASH160, byte(len(pkval))}, pkval...), OP_EQUALVERIFY, OP_CHECKSIG)
}

func PayToPubkeyAddr(script []byte) []byte {
	if len(script) < 6 {
		return nil
	}
	if script[0] != OP_DUP || script[1] != OP_HASH160 || script[len(script)-1] != OP_CHECKSIG || script[len(script)-2] != OP_EQUALVERIFY {
		return nil
	}

	return script[3 : len(script)-2]
}

func PayToScriptHashAddr(script []byte) []byte {
	if len(script) < 4 || script[0] != OP_HASH160 || script[len(script)-1] != OP_EQUAL {
		return nil
	}

	return script[2 : len(script)-1]
}

const (
	AddressTypeNonStandard = 0
	AddressTypeP2PKH       = 1
	AddressTypeP2SH        = 2
)

func ExtractAddressFromScript(script []byte) ([]byte, int, error) {
	a := PayToPubkeyAddr(script)
	if a != nil {
		return a, AddressTypeP2PKH, nil
	}

	a = PayToScriptHashAddr(script)
	if a != nil {
		return a, AddressTypeP2SH, nil
	}

	return nil, 0, nil
}

func MakeMultisig(m, n int, pubks [][]byte) []byte {
	out := new(bytes.Buffer)
	out.WriteByte(byte(0x50 + m))
	for _, k := range pubks {
		out.WriteByte(byte(len(k)))
		out.Write(k)
	}
	out.WriteByte(byte(0x50 + n))
	out.WriteByte(OP_CHECKMULTISIG)
	return out.Bytes()
}
