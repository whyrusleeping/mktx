package mktx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

type Tx struct {
	Version  uint32   `json:"version"`
	Inputs   []*TxIn  `json:"inputs"`
	Outputs  []*TxOut `json:"outputs"`
	LockTime uint32   `json:"lockTime"`
	//JoinSplits []*JSDescription `json:"joinSplits,omitempty"`
	JSPubKey []byte `json:"jsPubKey,omitempty"`
	JSSig    []byte `json:"jsSig,omitempty"`
}

func (t *Tx) RawData() []byte {
	buf := new(bytes.Buffer)
	i := make([]byte, 4)
	binary.LittleEndian.PutUint32(i, t.Version)
	buf.Write(i)
	writeVarInt(buf, uint64(len(t.Inputs)))
	for _, inp := range t.Inputs {
		inp.WriteTo(buf)
	}

	writeVarInt(buf, uint64(len(t.Outputs)))
	for _, out := range t.Outputs {
		out.WriteTo(buf)
	}

	binary.LittleEndian.PutUint32(i, t.LockTime)
	buf.Write(i)
	if t.Version == 1 {
		return buf.Bytes()
	}

	panic("unsupported")
	/*
		writeVarInt(buf, uint64(len(t.JoinSplits)))
		for _, js := range t.JoinSplits {
			js.WriteTo(buf)
		}
	*/

	buf.Write(t.JSPubKey)
	buf.Write(t.JSSig)

	return buf.Bytes()
}

func (t *Tx) String() string {
	return fmt.Sprintf("zcash transaction")
}

type TxIn struct {
	PrevTx      string `json:"prevTx,omitempty"`
	PrevTxIndex uint32 `json:"prevTxIndex"`
	Script      []byte `json:"script"`
	SeqNo       uint32 `json:"seqNo"`
}

func reverse(d []byte) []byte {
	out := make([]byte, len(d))
	for i, v := range d {
		out[len(d)-(i+1)] = v
	}
	return out
}

func (i *TxIn) WriteTo(w io.Writer) error {
	buf := make([]byte, 36)
	if i.PrevTx != "" {
		val, err := hex.DecodeString(i.PrevTx)
		if err != nil {
			return err
		}

		copy(buf[:32], reverse(val))
	}
	binary.LittleEndian.PutUint32(buf[32:36], i.PrevTxIndex)
	w.Write(buf)

	writeVarInt(w, uint64(len(i.Script)))
	w.Write(i.Script)
	binary.LittleEndian.PutUint32(buf[:4], i.SeqNo)
	w.Write(buf[:4])
	return nil
}

type TxOut struct {
	Value  uint64 `json:"value"`
	Script []byte `json:"script"`
}

func (o *TxOut) WriteTo(w io.Writer) error {
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, o.Value)
	w.Write(val)
	writeVarInt(w, uint64(len(o.Script)))
	w.Write(o.Script)
	return nil
}
