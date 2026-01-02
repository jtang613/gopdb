// Package streams provides parsers for the various PDB streams.
package streams

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PDB Stream versions
const (
	PDBStreamVersionVC2       = 19941610
	PDBStreamVersionVC4       = 19950623
	PDBStreamVersionVC41      = 19950814
	PDBStreamVersionVC50      = 19960307
	PDBStreamVersionVC98      = 19970604
	PDBStreamVersionVC70Dep   = 19990604
	PDBStreamVersionVC70      = 20000404
	PDBStreamVersionVC80      = 20030901
	PDBStreamVersionVC110     = 20091201
	PDBStreamVersionVC140     = 20140508
)

// PDBInfo represents the PDB Info Stream (Stream 1).
type PDBInfo struct {
	Version       uint32
	Signature     uint32    // Timestamp of PDB creation
	Age           uint32    // Number of times PDB has been written
	GUID          [16]byte  // Unique identifier
	NamedStreams  map[string]uint32 // Map of named streams to stream indices
}

// PDBInfoHeader is the fixed header at the start of the PDB info stream.
type PDBInfoHeader struct {
	Version   uint32
	Signature uint32
	Age       uint32
	GUID      [16]byte
}

// ReadPDBInfo parses the PDB info stream.
func ReadPDBInfo(r io.Reader) (*PDBInfo, error) {
	var header PDBInfoHeader
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read PDB info header: %w", err)
	}

	info := &PDBInfo{
		Version:      header.Version,
		Signature:   header.Signature,
		Age:         header.Age,
		GUID:        header.GUID,
		NamedStreams: make(map[string]uint32),
	}

	// Read the named stream map
	// Format: StringTableSize + StringTable + HashTableSize + HashTable

	// Read string buffer size
	var strBufSize uint32
	if err := binary.Read(r, binary.LittleEndian, &strBufSize); err != nil {
		// Named streams might not be present in older PDBs
		return info, nil
	}

	// Read string buffer
	strBuf := make([]byte, strBufSize)
	if _, err := io.ReadFull(r, strBuf); err != nil {
		return info, nil
	}

	// Read hash table size
	var hashSize uint32
	if err := binary.Read(r, binary.LittleEndian, &hashSize); err != nil {
		return info, nil
	}

	// Read hash table capacity
	var hashCapacity uint32
	if err := binary.Read(r, binary.LittleEndian, &hashCapacity); err != nil {
		return info, nil
	}

	// Read present bit vector
	var presentWordsCount uint32
	if err := binary.Read(r, binary.LittleEndian, &presentWordsCount); err != nil {
		return info, nil
	}
	presentWords := make([]uint32, presentWordsCount)
	if err := binary.Read(r, binary.LittleEndian, presentWords); err != nil {
		return info, nil
	}

	// Read deleted bit vector
	var deletedWordsCount uint32
	if err := binary.Read(r, binary.LittleEndian, &deletedWordsCount); err != nil {
		return info, nil
	}
	deletedWords := make([]uint32, deletedWordsCount)
	if err := binary.Read(r, binary.LittleEndian, deletedWords); err != nil {
		return info, nil
	}

	// Read key-value pairs for present buckets
	for i := uint32(0); i < hashCapacity; i++ {
		if !isBitSet(presentWords, i) {
			continue
		}

		var keyOffset uint32
		var streamIndex uint32
		if err := binary.Read(r, binary.LittleEndian, &keyOffset); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &streamIndex); err != nil {
			break
		}

		// Extract string from buffer
		if keyOffset < strBufSize {
			name := extractCString(strBuf[keyOffset:])
			info.NamedStreams[name] = streamIndex
		}
	}

	return info, nil
}

// GUIDString returns the GUID as a formatted string.
func (p *PDBInfo) GUIDString() string {
	return fmt.Sprintf("%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		binary.LittleEndian.Uint32(p.GUID[0:4]),
		binary.LittleEndian.Uint16(p.GUID[4:6]),
		binary.LittleEndian.Uint16(p.GUID[6:8]),
		p.GUID[8], p.GUID[9], p.GUID[10], p.GUID[11],
		p.GUID[12], p.GUID[13], p.GUID[14], p.GUID[15])
}

// isBitSet checks if bit n is set in the bit vector.
func isBitSet(words []uint32, n uint32) bool {
	wordIdx := n / 32
	bitIdx := n % 32
	if wordIdx >= uint32(len(words)) {
		return false
	}
	return (words[wordIdx] & (1 << bitIdx)) != 0
}

// extractCString extracts a null-terminated string from bytes.
func extractCString(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		return string(data)
	}
	return string(data[:idx])
}
