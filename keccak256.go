package main

import (
	"encoding/binary"
)

//go:wasmimport env wasm_input
//go:noescape
func wasm_input(isPublic uint32) uint64

//go:wasmimport env require
//go:noescape
func require(uint32)

//go:wasmimport env keccak_new
//go:noescape
func keccak_new(uint64)

//go:wasmimport env keccak_push
//go:noescape
func keccak_push(uint64)

//go:wasmimport env keccak_finalize
//go:noescape
func keccak_finalize() uint64

func require_bool(cond bool) {
	if cond {
		require(1)
	} else {
		require(0)
	}
}

type KeccakHasher struct {
	data    uint64
	byteIdx uint64
	bufSize uint64
}

func NewKeccakHasher() *KeccakHasher {
	keccak_new(1)
	return &KeccakHasher{
		data:    0,
		byteIdx: 0,
		bufSize: 0,
	}
}

func (kh *KeccakHasher) UpdateByte(v byte) {
	kh.data += uint64(v) << (kh.byteIdx * 8)
	kh.byteIdx++
	if kh.byteIdx >= 8 {
		keccak_push(kh.data)
		kh.data = 0
		kh.byteIdx = 0
		kh.bufSize++

		if kh.bufSize == 17 {
			keccak_finalize()
			keccak_finalize()
			keccak_finalize()
			keccak_finalize()
			keccak_new(0)
			kh.bufSize = 0
		}
	}
}

func (kh *KeccakHasher) Finalize() [4]uint64 {
	bytesToPad := 136 - kh.byteIdx - kh.bufSize*8
	if bytesToPad == 1 {
		var result uint64 = 0x86 << 56
		keccak_push(kh.data + result)
	} else {
		kh.UpdateByte(1)
		for i := 0; i < int(bytesToPad)-2; i++ {
			kh.UpdateByte(0)
		}
		var result uint64 = 0x80 << 56
		keccak_push(kh.data + result)
	}

	return [4]uint64{
		keccak_finalize(),
		keccak_finalize(),
		keccak_finalize(),
		keccak_finalize(),
	}
}

func Keccak256Hash(data ...[]byte) (output [32]byte) {
	hasher := NewKeccakHasher()
	for _, value := range data {
		for _, byteValue := range value {
			hasher.UpdateByte(byteValue)
		}
	}
	result := hasher.Finalize()
	for i, val := range result {
		binary.LittleEndian.PutUint64(output[i*8:], val)
	}
	return output
}

func keccak256check(input []byte, output []byte) {
	result := Keccak256Hash(input)
	for i := 0; i < len(result); i++ {
		if result[i] != output[i] {
			require(1)
			require(0)
		}
	}
}

func main() {
	/*
		input := make([]byte, 0)
		emtpy_output := []byte{
			197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83,
			202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
		}
		keccak256check(input, emtpy_output)
	*/
	input := []byte{197}
	one_output := []byte{
		21, 191, 54, 255, 99, 225, 69, 172, 52, 26, 134, 0, 126, 137, 21, 92, 243, 18, 222, 79, 162, 167, 211, 173, 63, 188, 75, 120, 1, 3, 35, 72,
	}
	keccak256check(input, one_output)

	/*
		input = []byte{102, 111, 111, 98, 97, 114, 97, 97}
		short_output := []byte{
			172, 132, 33, 155, 248, 181, 178, 245, 199, 105, 157, 164, 188, 53, 193, 25, 7, 35, 159,
			188, 30, 123, 91, 143, 30, 100, 188, 128, 172, 248, 137, 202,
		}
		keccak256check(input, short_output)

		input = []byte{197}
		one_output := []byte{
			21, 191, 54, 255, 99, 225, 69, 172, 52, 26, 134, 0, 126, 137, 21, 92, 243, 18, 222, 79, 162, 167, 211, 173, 63, 188, 75, 120, 1, 3, 35, 72,
		}
		keccak256check(input, one_output)
	*/
}
